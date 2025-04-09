<?php
// Include the admin-class.php file which contains the ADMIN class and its methods.
require_once 'authentication/admin-class.php';

// Create an instance of the ADMIN class.
$admin = new ADMIN();

// Check if the admin user is logged in; if not, redirect to the homepage.
if(!$admin->isUserLoggedIn())
{
    $admin->redirect('../../');  // Redirect to the parent directory.
}

// Prepare an SQL query to fetch user data based on the admin's session ID.
$stmt = $admin->runQuery("SELECT * FROM user WHERE id = :id");

// Execute the query with the session ID as a parameter.
$stmt->execute(array(":id"=>$_SESSION['adminSession']));

// Fetch the user data as an associative array.
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ADMIN DASHBOARD</title>
</head>
<body>
    <!-- Display a welcome message with the admin's email address. -->
    <h1>WELCOME <?php echo $user_data['email']?></h1>
    <!-- Provide a sign-out button that links to the admin-class.php file with a sign-out action. -->
    <button><a href="authentication/admin-class.php?admin_signout">SIGN OUT</a></button>
</body>
</html>