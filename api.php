<?php
/*
=========================================================
NEXUS AUTOMATION - API
=========================================================

Dit bestand verzorgt:
- registreren
- inloggen
- uitloggen
- veilige sessiecookies
- gebruikersgegevens
- adminrechten
- downloadcredits
- beveiligde EXE/ZIP downloads
- eerste admin aanmaken

Vereisten:
- PHP 8+
- SQLite3 PHP extension

Bestanden:
    api.php
    nexus.db             (wordt automatisch aangemaakt)
    private_downloads/
        NEXUS_AUTOMATION.exe
        NEXUS_AUTOMATION.zip

BELANGRIJK:
Zet de downloads NIET in een publieke /downloads-map.
Gebruik private_downloads zodat niemand het bestand rechtstreeks
kan openen zonder via deze API te gaan.

=========================================================
*/

declare(strict_types=1);


/* =====================================================
   CONFIGURATIE
===================================================== */

/*
 * Zet dit op true als je HTTPS gebruikt.
 * Voor een echte online website moet dit TRUE zijn.
 */
const USE_SECURE_COOKIES = true;

/*
 * Verander deze sleutel naar een lange willekeurige geheime tekst.
 *
 * Voorbeeld:
 * "nexus-2026-verander-dit-naar-een-eigen-lange-geheime-sleutel"
 */
const SETUP_KEY = "jan_heeft_4_tenen_en_zijn_naam_is_janes_koen_halen_vermuelen_4";


/* =====================================================
   HEADERS / CORS
===================================================== */

header("Content-Type: application/json; charset=utf-8");

/*
 * Vervang dit door je echte GitHub Pages-adres.
 *
 * Bijvoorbeeld:
 * https://jouwnaam.github.io
 *
 * Laat NIET zomaar * staan voor een echte productie-installatie
 * wanneer je cookies gebruikt.
 */
$allowedOrigin = "https://astronaut8699.github.io";

if (
    isset($_SERVER["HTTP_ORIGIN"]) &&
    $_SERVER["HTTP_ORIGIN"] === $allowedOrigin
) {
    header("Access-Control-Allow-Origin: " . $allowedOrigin);
    header("Access-Control-Allow-Credentials: true");
}

header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}


/* =====================================================
   DATABASE
===================================================== */

$db = new SQLite3(__DIR__ . "/nexus.db");

$db->busyTimeout(5000);

$db->exec("
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        credits INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,

        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash);

    CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_sessions_expiry
    ON sessions(expires_at);
");


/* =====================================================
   HELPERS
===================================================== */

function respond(array $data, int $status = 200): never
{
    http_response_code($status);

    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE
    );

    exit;
}


function input(): array
{
    $raw = file_get_contents("php://input");

    if (!$raw) {
        return [];
    }

    $data = json_decode($raw, true);

    return is_array($data) ? $data : [];
}


function cleanString(mixed $value): string
{
    return trim((string)$value);
}


function normalizeEmail(string $email): string
{
    return strtolower(trim($email));
}


function validUsername(string $username): bool
{
    return (bool)preg_match(
        '/^[A-Za-z0-9_-]{3,32}$/',
        $username
    );
}


function validEmail(string $email): bool
{
    return filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    ) !== false;
}


function clientIp(): string
{
    return $_SERVER["REMOTE_ADDR"] ?? "unknown";
}


function hashSessionToken(string $token): string
{
    return hash("sha256", $token);
}


/* =====================================================
   SESSION COOKIE
===================================================== */

function setSessionCookie(
    string $token,
    int $expires
): void {

    setcookie(
        "nexus_session",
        $token,
        [
            "expires" => $expires,
            "path" => "/",
            "secure" => USE_SECURE_COOKIES,
            "httponly" => true,
            "samesite" => "None"
        ]
    );
}


function clearSessionCookie(): void
{
    setcookie(
        "nexus_session",
        "",
        [
            "expires" => time() - 3600,
            "path" => "/",
            "secure" => USE_SECURE_COOKIES,
            "httponly" => true,
            "samesite" => "None"
        ]
    );
}


/* =====================================================
   USER / SESSION
===================================================== */

function currentUser(): ?array
{
    global $db;

    if (empty($_COOKIE["nexus_session"])) {
        return null;
    }

    $token = (string)$_COOKIE["nexus_session"];

    if (strlen($token) < 32) {
        return null;
    }

    $tokenHash = hashSessionToken($token);

    $stmt = $db->prepare("
        SELECT
            users.id,
            users.username,
            users.email,
            users.password_hash,
            users.is_admin,
            users.credits,
            users.created_at
        FROM sessions
        INNER JOIN users
            ON users.id = sessions.user_id
        WHERE sessions.token_hash = :token
          AND sessions.expires_at > :now
        LIMIT 1
    ");

    $stmt->bindValue(
        ":token",
        $tokenHash,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":now",
        time(),
        SQLITE3_INTEGER
    );

    $result = $stmt->execute();

    if (!$result) {
        return null;
    }

    $user = $result->fetchArray(
        SQLITE3_ASSOC
    );

    return $user ?: null;
}


function requireLogin(): array
{
    $user = currentUser();

    if (!$user) {
        respond([
            "success" => false,
            "message" => "Je moet eerst inloggen."
        ], 401);
    }

    return $user;
}


function requireAdmin(): array
{
    $user = requireLogin();

    if ((int)$user["is_admin"] !== 1) {
        respond([
            "success" => false,
            "message" => "Je hebt geen adminrechten."
        ], 403);
    }

    return $user;
}


function createSession(int $userId): void
{
    global $db;

    /*
     * Oude verlopen sessies opruimen.
     */
    $db->exec("
        DELETE FROM sessions
        WHERE expires_at <= " . time()
    );

    $token = bin2hex(
        random_bytes(32)
    );

    $tokenHash = hashSessionToken($token);

    $expires = time()
        + (30 * 24 * 60 * 60);

    $stmt = $db->prepare("
        INSERT INTO sessions
        (
            user_id,
            token_hash,
            expires_at,
            created_at
        )
        VALUES
        (
            :user,
            :token,
            :expires,
            :created
        )
    ");

    $stmt->bindValue(
        ":user",
        $userId,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ":token",
        $tokenHash,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":expires",
        $expires,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ":created",
        time(),
        SQLITE3_INTEGER
    );

    $stmt->execute();

    setSessionCookie(
        $token,
        $expires
    );
}


/* =====================================================
   REGISTER
===================================================== */

function registerUser(): void
{
    global $db;

    $data = input();

    $username = cleanString(
        $data["username"] ?? ""
    );

    $email = normalizeEmail(
        cleanString($data["email"] ?? "")
    );

    $password = (string)(
        $data["password"] ?? ""
    );


    if (
        $username === "" ||
        $email === "" ||
        $password === ""
    ) {
        respond([
            "success" => false,
            "message" => "Vul alle velden in."
        ], 400);
    }


    if (!validUsername($username)) {
        respond([
            "success" => false,
            "message" =>
                "Gebruikersnaam moet 3-32 tekens bevatten en mag alleen letters, cijfers, _ en - gebruiken."
        ], 400);
    }


    if (!validEmail($email)) {
        respond([
            "success" => false,
            "message" =>
                "Vul een geldig e-mailadres in."
        ], 400);
    }


    if (strlen($password) < 8) {
        respond([
            "success" => false,
            "message" =>
                "Wachtwoord moet minimaal 8 tekens bevatten."
        ], 400);
    }


    $check = $db->prepare("
        SELECT id
        FROM users
        WHERE email = :email
           OR username = :username
        LIMIT 1
    ");

    $check->bindValue(
        ":email",
        $email,
        SQLITE3_TEXT
    );

    $check->bindValue(
        ":username",
        $username,
        SQLITE3_TEXT
    );

    $existing = $check->execute()
        ->fetchArray(SQLITE3_ASSOC);


    if ($existing) {
        respond([
            "success" => false,
            "message" =>
                "Gebruikersnaam of e-mailadres bestaat al."
        ], 409);
    }


    $passwordHash = password_hash(
        $password,
        PASSWORD_DEFAULT
    );


    $stmt = $db->prepare("
        INSERT INTO users
        (
            username,
            email,
            password_hash,
            is_admin,
            credits,
            created_at
        )
        VALUES
        (
            :username,
            :email,
            :password,
            0,
            0,
            :created
        )
    ");

    $stmt->bindValue(
        ":username",
        $username,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":email",
        $email,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":password",
        $passwordHash,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":created",
        time(),
        SQLITE3_INTEGER
    );


    if (!$stmt->execute()) {
        respond([
            "success" => false,
            "message" =>
                "Account kon niet worden aangemaakt."
        ], 500);
    }


    respond([
        "success" => true,
        "message" =>
            "Account aangemaakt. Je kunt nu inloggen."
    ]);
}


/* =====================================================
   LOGIN
===================================================== */

function loginUser(): void
{
    global $db;

    $data = input();

    $email = normalizeEmail(
        cleanString($data["email"] ?? "")
    );

    $password = (string)(
        $data["password"] ?? ""
    );


    if (
        $email === "" ||
        $password === ""
    ) {
        respond([
            "success" => false,
            "message" =>
                "Vul e-mail en wachtwoord in."
        ], 400);
    }


    $stmt = $db->prepare("
        SELECT *
        FROM users
        WHERE email = :email
        LIMIT 1
    ");

    $stmt->bindValue(
        ":email",
        $email,
        SQLITE3_TEXT
    );

    $result = $stmt->execute();

    $user = $result
        ? $result->fetchArray(SQLITE3_ASSOC)
        : false;


    if (
        !$user ||
        !password_verify(
            $password,
            $user["password_hash"]
        )
    ) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldige login."
        ], 401);
    }


    /*
     * Nieuwe login krijgt een nieuwe sessie.
     */
    createSession(
        (int)$user["id"]
    );


    respond([
        "success" => true,
        "message" => "Ingelogd."
    ]);
}


/* =====================================================
   LOGOUT
===================================================== */

function logoutUser(): void
{
    global $db;

    if (!empty($_COOKIE["nexus_session"])) {

        $tokenHash = hashSessionToken(
            (string)$_COOKIE["nexus_session"]
        );

        $stmt = $db->prepare("
            DELETE FROM sessions
            WHERE token_hash = :token
        ");

        $stmt->bindValue(
            ":token",
            $tokenHash,
            SQLITE3_TEXT
        );

        $stmt->execute();
    }

    clearSessionCookie();

    respond([
        "success" => true,
        "message" => "Uitgelogd."
    ]);
}


/* =====================================================
   CURRENT ACCOUNT
===================================================== */

function me(): void
{
    $user = currentUser();

    if (!$user) {
        respond([
            "loggedIn" => false
        ]);
    }


    respond([
        "loggedIn" => true,

        "user" => [
            "id" =>
                (int)$user["id"],

            "username" =>
                $user["username"],

            "email" =>
                $user["email"],

            "admin" =>
                (int)$user["is_admin"] === 1,

            "credits" =>
                (int)$user["credits"]
        ]
    ]);
}


/* =====================================================
   ADMIN - USERS
===================================================== */

function adminUsers(): void
{
    requireAdmin();

    global $db;


    $result = $db->query("
        SELECT
            id,
            username,
            email,
            is_admin,
            credits,
            created_at

        FROM users

        ORDER BY id DESC
    ");


    $users = [];


    while ($row = $result->fetchArray(
        SQLITE3_ASSOC
    )) {

        $users[] = [
            "id" =>
                (int)$row["id"],

            "username" =>
                $row["username"],

            "email" =>
                $row["email"],

            "is_admin" =>
                (int)$row["is_admin"],

            "credits" =>
                (int)$row["credits"],

            "created_at" =>
                (int)$row["created_at"]
        ];
    }


    respond([
        "success" => true,
        "users" => $users
    ]);
}


/* =====================================================
   ADMIN - CREDITS GEVEN
===================================================== */

function giveCredits(): void
{
    requireAdmin();

    global $db;

    $data = input();

    $userId = (int)(
        $data["user_id"] ?? 0
    );

    $amount = (int)(
        $data["amount"] ?? 0
    );


    /*
     * We accepteren alleen positieve hoeveelheden.
     * Zo kan deze endpoint niet gebruikt worden om
     * credits weg te halen.
     */
    if (
        $userId <= 0 ||
        $amount <= 0 ||
        $amount > 10000
    ) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldig aantal credits."
        ], 400);
    }


    $check = $db->prepare("
        SELECT id
        FROM users
        WHERE id = :id
        LIMIT 1
    ");

    $check->bindValue(
        ":id",
        $userId,
        SQLITE3_INTEGER
    );

    $exists = $check->execute()
        ->fetchArray(SQLITE3_ASSOC);


    if (!$exists) {
        respond([
            "success" => false,
            "message" =>
                "Gebruiker niet gevonden."
        ], 404);
    }


    $stmt = $db->prepare("
        UPDATE users

        SET credits = credits + :amount

        WHERE id = :id
    ");

    $stmt->bindValue(
        ":amount",
        $amount,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ":id",
        $userId,
        SQLITE3_INTEGER
    );

    $stmt->execute();


    respond([
        "success" => true,
        "message" =>
            "Credits toegevoegd."
    ]);
}


/* =====================================================
   ADMIN - ADMIN MAKEN
===================================================== */

function makeAdmin(): void
{
    requireAdmin();

    global $db;

    $data = input();

    $userId = (int)(
        $data["user_id"] ?? 0
    );


    if ($userId <= 0) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldige gebruiker."
        ], 400);
    }


    $stmt = $db->prepare("
        UPDATE users

        SET is_admin = 1

        WHERE id = :id
    ");

    $stmt->bindValue(
        ":id",
        $userId,
        SQLITE3_INTEGER
    );

    $stmt->execute();


    respond([
        "success" => true,
        "message" =>
            "Gebruiker is nu admin."
    ]);
}


/* =====================================================
   DOWNLOAD
===================================================== */

function downloadFile(): never
{
    $user = requireLogin();

    global $db;


    $type = strtolower(
        cleanString($_GET["type"] ?? "")
    );


    $files = [
        "exe" => [
            "name" =>
                "NEXUS_AUTOMATION.exe",

            "path" =>
                __DIR__ .
                "/private_downloads/NEXUS_AUTOMATION.exe",

            "mime" =>
                "application/octet-stream"
        ],

        "zip" => [
            "name" =>
                "NEXUS_AUTOMATION.zip",

            "path" =>
                __DIR__ .
                "/private_downloads/NEXUS_AUTOMATION.zip",

            "mime" =>
                "application/zip"
        ]
    ];


    if (!isset($files[$type])) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldig downloadtype."
        ], 400);
    }


    $file = $files[$type];


    if (!is_file($file["path"])) {
        respond([
            "success" => false,
            "message" =>
                "Downloadbestand is niet gevonden op de server."
        ], 404);
    }


    if ((int)$user["credits"] <= 0) {
        respond([
            "success" => false,
            "message" =>
                "Je hebt geen downloadcredits."
        ], 403);
    }


    /*
     * Transaction:
     *
     * 1. Controleer opnieuw dat de gebruiker minstens
     *    één credit heeft.
     *
     * 2. Trek exact één credit af.
     *
     * 3. Pas daarna sturen we het bestand.
     *
     * Dit voorkomt dat twee gelijktijdige requests
     * dezelfde credit gebruiken.
     */
    $db->exec("BEGIN IMMEDIATE TRANSACTION");


    try {

        $stmt = $db->prepare("
            UPDATE users

            SET credits = credits - 1

            WHERE id = :id

              AND credits > 0
        ");

        $stmt->bindValue(
            ":id",
            (int)$user["id"],
            SQLITE3_INTEGER
        );

        $stmt->execute();


        if ($db->changes() !== 1) {

            $db->exec("ROLLBACK");

            respond([
                "success" => false,
                "message" =>
                    "Je hebt geen downloadcredit meer."
            ], 403);
        }


        $db->exec("COMMIT");


    } catch (Throwable $e) {

        $db->exec("ROLLBACK");

        respond([
            "success" => false,
            "message" =>
                "Download kon niet worden voorbereid."
        ], 500);
    }


    /*
     * Vanaf hier sturen we GEEN JSON meer.
     */
    header_remove("Content-Type");

    header(
        "Content-Type: " .
        $file["mime"]
    );

    header(
        "Content-Disposition: attachment; filename=\"" .
        $file["name"] .
        "\""
    );

    header(
        "Content-Length: " .
        filesize($file["path"])
    );

    header("X-Content-Type-Options: nosniff");

    header("Cache-Control: private, no-store");

    readfile($file["path"]);

    exit;
}


/* =====================================================
   FIRST ADMIN SETUP
===================================================== */

/*
 * Deze route is bedoeld om de ALLEREERSTE admin te maken.
 *
 * Gebruik:
 *
 * POST api.php?action=create_first_admin
 *
 * Header:
 * Content-Type: application/json
 *
 * Body:
 * {
 *   "setup_key": "jouw-geheime-key",
 *   "username": "admin",
 *   "email": "jouw-email",
 *   "password": "een-sterk-wachtwoord"
 * }
 *
 * Nadat je de eerste admin hebt gemaakt, verander SETUP_KEY
 * hierboven naar een andere lange willekeurige tekst.
 */

function createFirstAdmin(): void
{
    global $db;

    $data = input();


    $setupKey = (string)(
        $data["setup_key"] ?? ""
    );


    if (
        SETUP_KEY ===
        "VERANDER-DIT-IN-EEN-LANGE-GEHEIME-SETUP-KEY"
    ) {
        respond([
            "success" => false,
            "message" =>
                "Verander eerst SETUP_KEY in api.php."
        ], 500);
    }


    if (
        !hash_equals(
            SETUP_KEY,
            $setupKey
        )
    ) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldige setup key."
        ], 403);
    }


    $count = $db->querySingle(
        "SELECT COUNT(*) FROM users"
    );


    /*
     * Alleen toegestaan wanneer de database nog
     * geen gebruikers bevat.
     */
    if ((int)$count > 0) {
        respond([
            "success" => false,
            "message" =>
                "Er bestaat al een gebruiker. Eerste admin setup is gesloten."
        ], 403);
    }


    $username = cleanString(
        $data["username"] ?? ""
    );

    $email = normalizeEmail(
        cleanString($data["email"] ?? "")
    );

    $password = (string)(
        $data["password"] ?? ""
    );


    if (!validUsername($username)) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldige gebruikersnaam."
        ], 400);
    }


    if (!validEmail($email)) {
        respond([
            "success" => false,
            "message" =>
                "Ongeldig e-mailadres."
        ], 400);
    }


    if (strlen($password) < 8) {
        respond([
            "success" => false,
            "message" =>
                "Wachtwoord moet minimaal 8 tekens bevatten."
        ], 400);
    }


    $hash = password_hash(
        $password,
        PASSWORD_DEFAULT
    );


    $stmt = $db->prepare("
        INSERT INTO users
        (
            username,
            email,
            password_hash,
            is_admin,
            credits,
            created_at
        )
        VALUES
        (
            :username,
            :email,
            :password,
            1,
            0,
            :created
        )
    ");


    $stmt->bindValue(
        ":username",
        $username,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":email",
        $email,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":password",
        $hash,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ":created",
        time(),
        SQLITE3_INTEGER
    );


    if (!$stmt->execute()) {
        respond([
            "success" => false,
            "message" =>
                "Admin kon niet worden aangemaakt."
        ], 500);
    }


    respond([
        "success" => true,
        "message" =>
            "Eerste admin is aangemaakt."
    ]);
}


/* =====================================================
   ROUTER
===================================================== */

$action = cleanString(
    $_GET["action"] ?? ""
);


switch ($action) {

    case "register":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        registerUser();
        break;


    case "login":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        loginUser();
        break;


    case "logout":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        logoutUser();
        break;


    case "me":
        if ($_SERVER["REQUEST_METHOD"] !== "GET") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik GET."
            ], 405);
        }

        me();
        break;


    case "admin_users":
        if ($_SERVER["REQUEST_METHOD"] !== "GET") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik GET."
            ], 405);
        }

        adminUsers();
        break;


    case "give_credits":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        giveCredits();
        break;


    case "make_admin":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        makeAdmin();
        break;


    case "download":
        if ($_SERVER["REQUEST_METHOD"] !== "GET") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik GET."
            ], 405);
        }

        downloadFile();
        break;


    case "create_first_admin":
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            respond([
                "success" => false,
                "message" =>
                    "Gebruik POST."
            ], 405);
        }

        createFirstAdmin();
        break;


    default:

        respond([
            "success" => true,
            "name" =>
                "NEXUS AUTOMATION API",
            "status" =>
                "online"
        ]);
}
?>
