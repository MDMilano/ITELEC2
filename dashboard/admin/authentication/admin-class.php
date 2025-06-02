<?php
require_once __DIR__ . '/../../../database/dbconnection.php';
include_once __DIR__ . '/../../../config/settings-configuration.php';
require_once __DIR__ . '/../../../src/vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class ADMIN
{
    private $conn;
    private $settings;
    private $smtp_email;
    private $smtp_password;

    public function __construct()
    {
        $this->settings = new SystemConfig();
        $this->smtp_email = $this->settings->getSmtpEmail();
        $this->smtp_password = $this->settings->getSmtpPassword();

        $database = new Database();
        $this->conn =  $database->dbConnection();
    }

    public function sendOtp($otp, $email){
        if ($email == NULL){
            echo "<script>alert('No email found'); window.location.href='../../../';</script>";
            exit;
        }else{
            $stmt = $this->runQuery("SELECT * FROM user WHERE email =:email");
            $stmt->execute(array(":email" => $email));
            $stmt->fetch(PDO::FETCH_ASSOC);

            if($stmt->rowCount() > 0){
                echo "<script>alert('Email already taken. Please try another one.'); window.location.href='../../../';</script>";
                exit;
            }else{
                $_SESSION['OTP'] = $otp;

                $subject = "OTP VERIFICATION";
                $message = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>OTP VERIFICATION</title>
                    <style>
                        body {
                            font-family: Arial, Helvetica, sans-serif;
                            background-color: #f5f5f5;
                            margin: 0;
                            padding: 0;
                        }

                        .container{
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 30px;
                            background-color: #ffffff;
                            border-radius: 4px;
                            box-shadow: 0 2 px 4px rgba(0, 0, 0, 0.1);
                        }

                        h1 {
                            color: #333333;
                            font-size: 24px;
                            margin-bottom: 20px;
                        }

                        p {
                            color: #666666;
                            font-size: 16px;
                            margin-bottom: 10px;
                        }

                        button {
                            display: inline-block;
                            padding: 12px 24px;
                            background-color: #0088cc;
                            color: #ffffff;
                            text-decoration: none;
                            border-radius: 4px;
                            font-size: 16px;
                            margin-top: 20px;
                        }

                        .logo {
                            display: block;
                            text-align: center;
                            margin-bottom: 30px;
                        }
                    </style>
                </head>
                <body>
                        <div class='container'>
                            <div class='logo'>
                                <img src='cid:logo' alt='logo' width='150'>
                            </div>
                            <h1>OTP VERIFICATION</h1>
                            <p>Hello, $email</p>
                            <p>Your OTP is: $otp</p>
                            <p>If you didn't request an OTP, please ignore this email.</p>
                            <p>Thank you!</p>
                        </div>
                </body>
                </html>";

                $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
                echo "<script>alert('We sent the OTP to $email'); window.location.href='../../../verify-otp.php';</script>";
            }
        }
    }

    public function verifyOTP($username, $email, $password, $otp, $csrf_token){
        if($otp == $_SESSION['OTP']){
            unset($_SESSION['OTP']);

            $status = "active";
            $this->addAdmin($csrf_token, $username, $email, $password, $status);

            $subject = "VERIFICATION SUCCESS";
            $message = "
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>VERIFICATION SUCCESS</title>
                <style>
                    body {
                        font-family: Arial, Helvetica, sans-serif;
                        background-color: #f5f5f5;
                        margin: 0;
                        padding: 0;
                    }

                    .container{
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 30px;
                        background-color: #ffffff;
                        border-radius: 4px;
                        box-shadow: 0 2 px 4px rgba(0, 0, 0, 0.1);
                    }

                    h1 {
                        color: #333333;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }

                    p {
                        color: #666666;
                        font-size: 16px;
                        margin-bottom: 10px;
                    }

                    button {
                        display: inline-block;
                        padding: 12px 24px;
                        background-color: #0088cc;
                        color: #ffffff;
                        text-decoration: none;
                        border-radius: 4px;
                        font-size: 16px;
                        margin-top: 20px;
                    }

                    .logo {
                        display: block;
                        text-align: center;
                        margin-bottom: 30px;
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='logo'>
                        <img src='cid:logo' alt='logo' width='150'>
                    </div>
                    <h1>Welcome</h1>
                    <p>Hello, <strong>$email</strong></strong></p>
                    <p>Welcome to Marc System</p>
                    <p>If you did not sign up for an account, you can safely ignore this email.</p>
                    <p>Thank you!</p>
                </div>
            </body>
            </html>";

            $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
            echo "<script>alert('Thank You'); window.location.href='../../../';</script>";

            unset($_SESSION['verify_not_username']);
            unset($_SESSION['verify_not_email']);
            unset($_SESSION['verify_not_password']);
        }else if ($otp == NULL){
            echo "<script>alert('No OTP Found'); window.location.href='../../../verify-otp.php';</script>";
            exit;
        }else{
            echo "<script>alert('It appears that the OTP you entered is invalid'); window.location.href='../../../verify-otp.php';</script>";
            exit;
        }
    }

    public function addAdmin($csrf_token, $username, $email, $password, $status)
    {
        $stmt = $this->runQuery("SELECT * FROM user WHERE email =:email");
        $stmt->execute(array(":email" => $email));

        if($stmt->rowCount() > 0){
            echo "<script>alert('Email already exists!'); window.location.href='../../../';</script>";
            exit;
        }

        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);
        
        $hash_password = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $this->runQuery("INSERT INTO user (username, email, password, status) VALUES (:username, :email, :password, :status)");
        $exec = $stmt->execute(array(
            ":username" => $username,
            ":email" => $email,
            ":password" => $hash_password,
            ":status" => $status
        ));

        if($exec){
            echo "<script>alert('Admin Added Successfully!');</script>";
        } else {
            echo "<script>alert('Error Adding Admin!'); window.location.href='../../../';</script>";
            exit;
        }
    }

    public function adminSignin($email, $password, $csrf_token)
    {
        try{
            if(empty($email) || empty($password)){
                echo "<script>alert('Please fill in all fields!'); window.location.href='../../../';</script>";
                exit;
            }

            if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
                echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../';</script>";
                exit;
            }

            unset($_SESSION['csrf_token']);

            $stmt = $this->runQuery("SELECT * FROM user WHERE email = :email AND status = :status");
            $stmt->execute(array(":email" => $email, ":status" => "active"));
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

            if($stmt->rowCount() == 1){
                if($userRow['status'] == 'active'){
                    if(password_verify($password, $userRow['password'])){
                        $activity = "Has Successfully signed in";
                        $user_id = $userRow['id'];
                        $this->logs($activity, $user_id);

                        $_SESSION['adminSession'] = $user_id;

                        echo "<script>alert('Welcome!'); window.location.href='../';</script>";
                        exit;
                    }else{
                        echo "<script>alert('Password is incorrect'); window.location.href='../../../';</script>";
                        exit;
                    }
                }else{
                    echo "<script>alert('Entered email is not verify'); window.location.href='../../../';</script>";
                    exit;
                }
            }else{
                echo "<script>alert('No account found'); window.location.href='../../../';</script>";
                exit;
            }
        }catch(PDOException $ex){
            echo $ex->getMessage();
        }
    }

    public function forgotPassword($csrf_token, $email, $token)
    {
        if(empty($email)){
            echo "<script>alert('Please enter email!'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }

        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);

        $stmt = $this->runQuery("SELECT * FROM user WHERE email =:email");
        $stmt->execute(array(":email" => $email));

        if($stmt->rowCount() > 0){
            // Delete any existing reset tokens for this user
            $delete_stmt = $this->runQuery("DELETE FROM password_resets WHERE email = :email");
            $delete_stmt->bindParam(":email", $email);
            $delete_stmt->execute();
            
            // Insert new reset token
            $insert_stmt = $this->runQuery("INSERT INTO password_resets (email, token, created_at, expires_at) 
                            VALUES (:email, :token, now(), now() +interval 10 minute)");
            $insert_stmt->bindParam(":email", $email);
            $insert_stmt->bindParam(":token", $token);
            
            if($insert_stmt->execute()){
                // Create reset link
                $reset_link = "http://" . $_SERVER['HTTP_HOST'] . 
                                "/ITELEC2/reset-password.php?token=" . $token;
                
                $subject = "Password Reset Request";
                $message = "Hello,<br><br>";
                $message .= "You have requested to reset your password.<br><br>";
                $message .= "Please click the following link to reset your password:<br>";
                $message .= "<a href='" . $reset_link . "'>" . $reset_link . "</a><br><br>";
                $message .= "This link will expire in 10 minutes.<br><br>";
                $message .= "If you did not request this password reset, please ignore this email.<br><br>";
                $message .= "Best regards,<br>Marc";

                $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
                echo "<script>alert('Password reset instructions have been sent to your email.'); window.location.href='../../../';</script>";
                exit;
            }else{
                echo "<script>alert('Failed to create reset token. Please try again.'); window.location.href='../../../forgot-password.php';</script>";
                exit;
            }
        }else {
            echo "<script>alert('No Account found with that email'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }
    }

    public function resetPassword($token, $csrf_token, $new_reset_password, $confirm_new_password )
    {
        if(empty($token)){
            echo "<script>alert('No reset token provided.'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if(empty($new_reset_password) || empty($confirm_new_password)){
            echo "<script>alert('Please fill in all fields!'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if($new_reset_password !== $confirm_new_password){
            echo "<script>alert('Passwords do not match.'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);

        // Set timezone
        date_default_timezone_set('Asia/Manila');

        // Get current time
        $current_time = date('Y-m-d H:i:s');

        $query = "SELECT pr.*, u.email, u.password
                    FROM password_resets pr 
                    JOIN user u ON pr.email = u.email 
                    WHERE pr.token = :token 
                    AND pr.created_at <= now()
                    AND pr.expires_at >= now()
                    LIMIT 1";
        
        $stmt = $this->runQuery($query);
        $stmt->bindParam(":token", $token);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $reset_data = $stmt->fetch(PDO::FETCH_ASSOC);

            if(password_verify($new_reset_password, $reset_data['password'])){
                echo "<script>alert('New password cannot be same to your old password.'); window.location.href='../../../reset-password.php?token=$token';</script>";
                exit;
            }

            $hashed_password = password_hash($new_reset_password, PASSWORD_DEFAULT);

            // Update password
            $update_stmt = $this->runQuery("UPDATE user SET password = :password WHERE email = :email");
            $update_stmt->bindParam(":password", $hashed_password);
            $update_stmt->bindParam(":email", $reset_data['email']);
            $update_stmt->execute();
            
            // Delete all reset tokens for this user
            $delete_stmt = $this->runQuery("DELETE FROM password_resets WHERE email = :email");
            $delete_stmt->bindParam(":email", $reset_data['email']);
            $delete_stmt->execute();

            echo "<script>alert('Password has been reset successfully. You can now login with your new password.'); window.location.href='../../../';</script>";
            exit;
        }else{
            // Check if token exists but expired
            $check_query = "SELECT expires_at FROM password_resets WHERE token = :token";
            $check_stmt = $this->runQuery($check_query);
            $check_stmt->bindParam(":token", $token);
            $check_stmt->execute();
            
            if ($check_stmt->rowCount() > 0) {
                $token_data = $check_stmt->fetch(PDO::FETCH_ASSOC);
                if ($token_data['expires_at'] < $current_time) {
                    echo "<script>alert('Reset token has expired. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                    exit;
                } else {
                    echo "<script>alert('Invalid reset token. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                    exit;
                }
            } else {
                echo "<script>alert('Invalid reset token. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                exit;
            }
        }
    }

    public function adminSignout()
    {   
        $activity = "Has Successfully signed out";
        $user_id = $_SESSION['adminSession'];
        $this->logs($activity, $user_id);

        session_start();
        session_unset();
        session_destroy();

        echo "<script>alert('Sign Out Successfully!'); window.location.href='../../../';</script>";
        exit;
    }

    private function send_email($email, $message, $subject, $smtp_email, $smtp_password){
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->SMTPDebug = 0;
        $mail->SMTPAuth = true;
        $mail->SMTPSecure = "tls";
        $mail->Host = "smtp.gmail.com";
        $mail->Port = 587;
        $mail->addAddress($email);
        $mail->Username = $smtp_email;
        $mail->Password = $smtp_password;
        $mail->setFrom($smtp_email, "Marc");
        $mail->Subject = $subject;
        $mail->msgHTML($message);
        $mail->Send();
    }

    private function logs($activity, $user_id)
    {
        $stmt = $this->conn->prepare("INSERT INTO logs (user_id, activity) VALUES (:user_id, :activity)");
        $stmt->execute(array(
            ":user_id" => $user_id,
            ":activity" => $activity
        ));
    }

    public function runQuery($sql)
    {
        $stmt = $this->conn->prepare($sql);
        return $stmt;
    }
}

if(isset($_POST['btn-signup'])){
    $_SESSION["not_verify_username"] = trim($_POST['username']);
    $_SESSION["not_verify_email"] = trim($_POST['email']);
    $_SESSION["not_verify_password"] = trim($_POST['password']);  
    
    $email = trim($_POST['email']);
    $otp = rand(100000, 999999);

    $addAdmin = new ADMIN();
    $addAdmin->sendOtp($otp, $email);
}

if (isset($_POST['btn-verify'])){
    $csrf_token = trim($_POST['csrf_token']);
    $username = $_SESSION["not_verify_username"];
    $email = $_SESSION["not_verify_email"];
    $password = $_SESSION["not_verify_password"];

    $otp = trim($_POST['otp']);

    $adminVerify = new ADMIN();
    $adminVerify->verifyOTP($username, $email, $password, $otp, $csrf_token);
}

if(isset($_POST['btn-signin'])){
    $csrf_token = trim($_POST['csrf_token']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    $adminSignin = new ADMIN();
    $adminSignin->adminSignin($email, $password, $csrf_token);
}

if(isset($_GET['admin_signout'])){
    $adminSignout = new ADMIN();
    $adminSignout->adminSignout();
}

if(isset($_POST['btn-forgot-password'])){
    $csrf_token = trim($_POST['csrf_token']);
    $email = trim($_POST['email']);

    $token = md5(uniqid(rand()));

    $forgotPassword = new ADMIN();
    $forgotPassword->forgotPassword($csrf_token, $email, $token);
}

if(isset($_POST['btn-reset-password'])){
    $csrf_token = trim($_POST['csrf_token']);
    $token = trim($_POST['token']);
    $new_reset_password = trim($_POST['new_password']);
    $confirm_new_password = trim($_POST['confirm_new_password']);

    $resetPassword = new ADMIN();
    $resetPassword->resetPassword($token, $csrf_token, $new_reset_password, $confirm_new_password);
}

?>