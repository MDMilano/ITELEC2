<?php
// Include the database connection file.
require_once __DIR__ . '/../../../database/dbconnection.php';
// Include the settings configuration file.
include_once __DIR__ . '/../../../config/settings-configuration.php';

// Define the ADMIN class to handle admin-related operations.
class ADMIN
{
    // Declare a private property to hold the database connection.
    private $conn;

    // Constructor method to initialize the database connection.
    public function __construct()
    {
        // Create a new instance of the Database class.
        $database = new Database();
        // Establish a database connection and assign it to the $conn property.
        $this->conn =  $database->dbConnection();
    }

    // Method to add a new admin user.
    public function addAdmin($csrf_token, $username, $email, $password)
    {
        // Prepare a query to check if the email already exists in the database.
        $stmt = $this->conn->prepare("SELECT * FROM user WHERE email =:email");
        // Execute the query with the provided email.
        $stmt->execute(array(":email" => $email));

        // If the email already exists, display an alert and redirect to the homepage.
        if($stmt->rowCount() > 0){
            echo "<script>alert('Email already exists!'); window.location.href='../../../';</script>";
            exit;
        }

        // Check if the CSRF token is valid.
        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            // If the CSRF token is invalid, display an alert and redirect to the homepage.
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../';</script>";
            exit;
        }

        // Unset the CSRF token from the session after validation.
        unset($_SESSION['csrf_token']);

        // Hash the password using MD5 for storage in the database.
        $hash_password = md5($password);

        // Prepare a query to insert the new admin user into the database.
        $stmt = $this->runQuery("INSERT INTO user (username, email, password) VALUES (:username, :email, :password)");
        // Execute the query with the provided username, email, and hashed password.
        $exec = $stmt->execute(array(
            ":username" => $username,
            ":email" => $email,
            ":password" => $hash_password
        ));

        // If the query is successful, display a success alert and redirect to the homepage.
        if($exec){
            echo "<script>alert('Admin Added Successfully!'); window.location.href='../../../';</script>";
            exit;
        } else {
            // If the query fails, display an error alert and redirect to the homepage.
            echo "<script>alert('Error Adding Admin!'); window.location.href='../../../';</script>";
            exit;
        }
    }

    // Method to handle admin sign-in.
    public function adminSignin($email, $password, $csrf_token)
    {
        try{
            // Check if the CSRF token is valid.
            if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
                // If the CSRF token is invalid, display an alert and redirect to the homepage.
                echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../';</script>";
                exit;
            }
            // Unset the CSRF token from the session after validation.
            unset($_SESSION['csrf_token']);

            // Prepare a query to fetch the user with the provided email.
            $stmt = $this->conn->prepare("SELECT * FROM user WHERE email = :email");
            // Execute the query with the provided email.
            $stmt->execute(array(":email" => $email));
            // Fetch the user data as an associative array.
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists and the password matches.
            if($stmt->rowCount() == 1 && $userRow['password'] == md5($password)){
                // Log the successful sign-in activity.
                $activity = "Has Successfully signed in";
                $user_id = $userRow['id'];
                $this->logs($activity, $user_id);

                // Store the user ID in the session to indicate the user is logged in.
                $_SESSION['adminSession'] = $user_id;

                // Display a welcome alert and redirect to the admin dashboard.
                echo "<script>alert('Welcome!'); window.location.href='../';</script>";
                exit;
            }else{
                // If the credentials are invalid, display an alert and redirect to the homepage.
                echo "<script>alert('Invalid Credentials!'); window.location.href='../../../';</script>";
                exit;
            }

        }catch(PDOException $ex){
            // Catch any database errors and display the error message.
            echo $ex->getMessage();
        }
    }
    
    // Method to handle admin sign-out.
    public function adminSignout()
    {
        // Unset the admin session to log the user out.
        unset($_SESSION['adminSession']);
        // Display a sign-out success alert and redirect to the homepage.
        echo "<script>alert('Sign Out Successfully!'); window.location.href='../../../';</script>";
        exit;
    }

    // Method to log admin activities.
    public function logs($activity, $user_id)
    {
        // Prepare a query to insert the activity log into the database.
        $stmt = $this->conn->prepare("INSERT INTO logs (user_id, activity) VALUES (:user_id, :activity)");
        // Execute the query with the provided user ID and activity description.
        $stmt->execute(array(
            ":user_id" => $user_id,
            ":activity" => $activity
        ));
    }

    // Method to check if an admin user is logged in.
    public function isUserLoggedIn()
    {
        // Return true if the admin session is set.
        if(isset($_SESSION['adminSession'])){
            return true;
        }
    }

    // Method to redirect users who are not logged in.
    public function redirect()
    {
        // Display an alert and redirect to the homepage.
        echo "<script>alert('Admin must logged in first!'); window.location.href='../../../';</script>";
        exit;
    }

    // Method to prepare and return a database query.
    public function runQuery($sql)
    {
        // Prepare the SQL query using the database connection.
        $stmt = $this->conn->prepare($sql);
        return $stmt;
    }
}

// Check if the sign-up button is clicked.
if(isset($_POST['btn-signup'])){
    // Retrieve and sanitize the input values.
    $csrf_token = trim($_POST['csrf_token']);
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Create a new instance of the ADMIN class and call the addAdmin method.
    $addAdmin = new ADMIN();
    $addAdmin->addAdmin($csrf_token, $username, $email, $password);
}

// Check if the sign-in button is clicked.
if(isset($_POST['btn-signin'])){
    // Retrieve and sanitize the input values.
    $csrf_token = trim($_POST['csrf_token']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Create a new instance of the ADMIN class and call the adminSignin method.
    $adminSignin = new ADMIN();
    $adminSignin->adminSignin($email, $password, $csrf_token);
}

// Check if the admin sign-out action is triggered.
if(isset($_GET['admin_signout'])){
    // Create a new instance of the ADMIN class and call the adminSignout method.
    $adminSignout = new ADMIN();
    $adminSignout->adminSignout();
}
?>