<?php

header("Content-Type: application/json");

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    exit;
}


/* =====================================================
   DATABASE
===================================================== */

$db = new SQLite3(__DIR__ . "/nexus.db");


$db->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        credits INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
");


$db->exec("
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires INTEGER NOT NULL
    )
");


/* =====================================================
   HELPERS
===================================================== */

function response($data, $code = 200)
{
    http_response_code($code);

    echo json_encode($data);

    exit;
}


function getInput()
{
    $input = file_get_contents("php://input");

    $data = json_decode($input, true);

    if (!is_array($data)) {
        return [];
    }

    return $data;
}


/* =====================================================
   COOKIE / SESSION
===================================================== */

function createSession($userId)
{
    global $db;

    $token = bin2hex(random_bytes(32));

    $expires = time() + (60 * 60 * 24 * 30);


    $stmt = $db->prepare("
        INSERT INTO sessions
        (user_id, token, expires)
        VALUES
        (:user, :token, :expires)
    ");

    $stmt->bindValue(":user", $userId, SQLITE3_INTEGER);
    $stmt->bindValue(":token", $token, SQLITE3_TEXT);
    $stmt->bindValue(":expires", $expires, SQLITE3_INTEGER);

    $stmt->execute();


    setcookie(
        "nexus_session",
        $token,
        [
            "expires" => $expires,
            "path" => "/",
            "secure" => true,
            "httponly" => true,
            "samesite" => "None"
        ]
    );
}


function getUser()
{
    global $db;


    if (!isset($_COOKIE["nexus_session"])) {
        return null;
    }


    $token = $_COOKIE["nexus_session"];


    $stmt = $db->prepare("
        SELECT users.*
        FROM sessions
        JOIN users
        ON users.id = sessions.user_id

        WHERE sessions.token = :token

        AND sessions.expires > :time
    ");


    $stmt->bindValue(
        ":token",
        $token,
        SQLITE3_TEXT
    );


    $stmt->bindValue(
        ":time",
        time(),
        SQLITE3_INTEGER
    );


    $result = $stmt->execute();

    return $result->fetchArray(SQLITE3_ASSOC) ?: null;
}


/* =====================================================
   REGISTER
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "register") {

    $data = getInput();


    $username = trim($data["username"] ?? "");
    $email = trim($data["email"] ?? "");
    $password = $data["password"] ?? "";


    if (!$username || !$email || !$password) {

        response([
            "success" => false,
            "message" => "Vul alles in."
        ], 400);

    }


    if (strlen($password) < 8) {

        response([
            "success" => false,
            "message" => "Wachtwoord moet minimaal 8 tekens zijn."
        ], 400);

    }


    $passwordHash = password_hash(
        $password,
        PASSWORD_DEFAULT
    );


    try {

        $stmt = $db->prepare("
            INSERT INTO users
            (username, email, password)
            VALUES
            (:username, :email, :password)
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


        $stmt->execute();


        response([
            "success" => true,
            "message" => "Account aangemaakt!"
        ]);

    }

    catch (Exception $e) {

        response([
            "success" => false,
            "message" => "Gebruikersnaam of e-mail bestaat al."
        ], 400);

    }
}


/* =====================================================
   LOGIN
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "login") {

    $data = getInput();


    $email = trim($data["email"] ?? "");
    $password = $data["password"] ?? "";


    $stmt = $db->prepare("
        SELECT *
        FROM users
        WHERE email = :email
    ");


    $stmt->bindValue(
        ":email",
        $email,
        SQLITE3_TEXT
    );


    $result = $stmt->execute();

    $user = $result->fetchArray(SQLITE3_ASSOC);


    if (!$user ||
        !password_verify(
            $password,
            $user["password"]
        )) {

        response([
            "success" => false,
            "message" => "Ongeldige login."
        ], 401);

    }


    createSession($user["id"]);


    response([
        "success" => true,
        "message" => "Ingelogd!"
    ]);
}


/* =====================================================
   LOGOUT
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "logout") {


    if (isset($_COOKIE["nexus_session"])) {

        $stmt = $db->prepare("
            DELETE FROM sessions
            WHERE token = :token
        ");

        $stmt->bindValue(
            ":token",
            $_COOKIE["nexus_session"],
            SQLITE3_TEXT
        );

        $stmt->execute();


        setcookie(
            "nexus_session",
            "",
            time() - 3600,
            "/"
        );
    }


    response([
        "success" => true
    ]);
}


/* =====================================================
   CURRENT USER
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "GET"
    && ($_GET["action"] ?? "") === "me") {


    $user = getUser();


    if (!$user) {

        response([
            "loggedIn" => false
        ]);

    }


    response([
        "loggedIn" => true,

        "user" => [
            "id" => $user["id"],
            "username" => $user["username"],
            "email" => $user["email"],
            "admin" => (bool)$user["is_admin"],
            "credits" => (int)$user["credits"]
        ]
    ]);
}


/* =====================================================
   ADMIN: USERS
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "GET"
    && ($_GET["action"] ?? "") === "admin_users") {


    $admin = getUser();


    if (!$admin || !$admin["is_admin"]) {

        response([
            "success" => false,
            "message" => "Geen toegang."
        ], 403);

    }


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


    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {

        $users[] = $row;

    }


    response([
        "success" => true,
        "users" => $users
    ]);
}


/* =====================================================
   ADMIN: CREDITS GEVEN
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "give_credits") {


    $admin = getUser();


    if (!$admin || !$admin["is_admin"]) {

        response([
            "success" => false,
            "message" => "Geen toegang."
        ], 403);

    }


    $data = getInput();


    $userId = intval($data["user_id"] ?? 0);
    $amount = intval($data["amount"] ?? 0);


    if ($userId <= 0 || $amount <= 0) {

        response([
            "success" => false,
            "message" => "Ongeldige gegevens."
        ], 400);

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


    response([
        "success" => true,
        "message" => "Credits toegevoegd."
    ]);
}


/* =====================================================
   ADMIN ACCOUNT AANMAKEN
===================================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "make_admin") {


    $admin = getUser();


    if (!$admin || !$admin["is_admin"]) {

        response([
            "success" => false,
            "message" => "Geen toegang."
        ], 403);

    }


    $data = getInput();

    $userId = intval($data["user_id"] ?? 0);


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


    response([
        "success" => true
    ]);
}


/* =====================================================
   UNKNOWN ACTION
===================================================== */

response([
    "success" => false,
    "message" => "Onbekende actie."
], 404);


if ($_SERVER["REQUEST_METHOD"] === "POST"
    && ($_GET["action"] ?? "") === "create_first_admin") {

    $data = getInput();

    $username = trim($data["username"] ?? "");
    $email = trim($data["email"] ?? "");
    $password = $data["password"] ?? "";

    if (!$username || !$email || !$password) {
        response([
            "success" => false,
            "message" => "Vul alles in."
        ], 400);
    }

    $hash = password_hash(
        $password,
        PASSWORD_DEFAULT
    );

    $stmt = $db->prepare("
        INSERT INTO users
        (username, email, password, is_admin, credits)
        VALUES
        (:username, :email, :password, 1, 0)
    ");

    $stmt->bindValue(":username", $username);
    $stmt->bindValue(":email", $email);
    $stmt->bindValue(":password", $hash);

    $stmt->execute();

    response([
        "success" => true,
        "message" => "Admin aangemaakt."
    ]);
}
