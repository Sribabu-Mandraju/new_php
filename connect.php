<?php
session_start();

// Error reporting for development (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

$email = "";
$errors = array();

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'project');
define('DB_CHARSET', 'utf8mb4');

// Improved database connection with error handling
try {
    $db = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if (!$db) {
        throw new Exception("Connection failed: " . mysqli_connect_error());
    }
    
    // Set proper character set
    if (!mysqli_set_charset($db, DB_CHARSET)) {
        throw new Exception("Error setting character set: " . mysqli_error($db));
    }
    
    // Set connection timeout
    mysqli_options($db, MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    
} catch (Exception $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Function to sanitize input
function sanitize_input($data) {
    global $db;
    return mysqli_real_escape_string($db, trim($data));
}

// Function to validate email
function is_valid_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

if (isset($_POST['reg_user'])) {
    $email = sanitize_input($_POST['email']);
    $password_1 = $_POST['password_1'];
    $password_2 = $_POST['password_2'];

    // Enhanced validation
    if (empty($email)) {
        array_push($errors, "Email is required");
    } elseif (!is_valid_email($email)) {
        array_push($errors, "Invalid email format");
    }
    
    if (empty($password_1)) {
        array_push($errors, "Password is required");
    } elseif (strlen($password_1) < 8) {
        array_push($errors, "Password must be at least 8 characters long");
    }
    
    if ($password_1 != $password_2) {
        array_push($errors, "The two passwords do not match");
    }

    // Check if email exists using prepared statement
    $stmt = mysqli_prepare($db, "SELECT email FROM users WHERE email = ? LIMIT 1");
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    
    if (mysqli_stmt_num_rows($stmt) > 0) {
        array_push($errors, "Email already exists");
    }
    mysqli_stmt_close($stmt);

    if (count($errors) == 0) {
        // Use password_hash instead of md5
        $hashed_password = password_hash($password_1, PASSWORD_DEFAULT);
        
        $stmt = mysqli_prepare($db, "INSERT INTO users (email, password) VALUES (?, ?)");
        mysqli_stmt_bind_param($stmt, "ss", $email, $hashed_password);
        
        if (mysqli_stmt_execute($stmt)) {
            $_SESSION['email'] = $email;
            $_SESSION['success'] = "You are now logged in";
            header('location: index.php');
            exit();
        } else {
            array_push($errors, "Registration failed: " . mysqli_error($db));
        }
        mysqli_stmt_close($stmt);
    }
}

if (isset($_POST['login_user'])) {
    $email = sanitize_input($_POST['email']);
    $password = $_POST['password'];

    if (empty($email)) {
        array_push($errors, "Email is required");
    }
    if (empty($password)) {
        array_push($errors, "Password is required");
    }

    if (count($errors) == 0) {
        $stmt = mysqli_prepare($db, "SELECT * FROM users WHERE email = ? LIMIT 1");
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($user = mysqli_fetch_assoc($result)) {
            if (password_verify($password, $user['password'])) {
                $_SESSION['email'] = $email;
                $_SESSION['success'] = "You are now logged in";
                header('location: index.php');
                exit();
            } else {
                array_push($errors, "Wrong email/password combination");
            }
        } else {
            array_push($errors, "Wrong email/password combination");
        }
        mysqli_stmt_close($stmt);
    }
}

// Close database connection
mysqli_close($db);
?>
