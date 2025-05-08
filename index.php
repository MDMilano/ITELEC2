<?php
    include_once 'config/settings-configuration.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ITELEC2</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="src/css/styles.css">
</head>
<body class="custom-bg min-vh-100 d-flex align-items-center py-5">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-12 col-md-6 col-lg-5 col-xl-4">
                <!-- Sign In Form -->
                <div id="signin-form" class="bg-white p-4 p-md-5 rounded shadow-sm mb-4">
                    <h2 class="text-center fw-light mb-4">SIGN IN</h2>
                    <form action="dashboard/admin/authentication/admin-class.php" method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="mb-3">
                            <input type="email" class="form-control" name="email" placeholder="Enter Email" required>
                        </div>
                        
                        <div class="mb-3">
                            <input type="password" class="form-control" name="password" placeholder="Enter Password" required>
                        </div>

                        <div class="d-flex justify-content-end mb-3">
                            <a href="forget-password.php" class="text-decoration-none form-links">Forgot your password?</a>
                        </div>
                        
                        <div class="d-grid mb-3">
                            <button type="submit" class="btn btn-primary" name="btn-signin">SIGN IN</button>
                        </div>
                        
                        <div class="text-center">
                            <p class="mb-0">Don't have an account? <span class="text-primary" role="button" onclick="toggleForms()">Register here</span></p>
                        </div>
                    </form>
                </div>
                
                <!-- Registration Form -->
                <div id="registration-form" class="bg-white p-4 p-md-5 rounded shadow-sm mb-4 d-none">
                    <h2 class="text-center fw-light mb-4">REGISTRATION</h2>
                    <form action="dashboard/admin/authentication/admin-class.php" method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="mb-3">
                            <input type="text" class="form-control" name="username" placeholder="Enter Username" required>
                        </div>
                        
                        <div class="mb-3">
                            <input type="email" class="form-control" name="email" placeholder="Enter Email" required>
                        </div>
                        
                        <div class="mb-3">
                            <input type="password" class="form-control" name="password" placeholder="Enter Password" required>
                        </div>
                        
                        <div class="d-grid mb-3">
                            <button type="submit" class="btn btn-primary" name="btn-signup">SIGN UP</button>
                        </div>
                        
                        <div class="text-center">
                            <p class="mb-0">Already have an account? <span class="text-primary" role="button" onclick="toggleForms()">Sign in here</span></p>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Toggle Forms Script -->
    <script>
        function toggleForms() {
            const signinForm = document.getElementById('signin-form');
            const registrationForm = document.getElementById('registration-form');
            
            if (signinForm.classList.contains('d-none')) {
                // Show signin, hide registration
                signinForm.classList.remove('d-none');
                registrationForm.classList.add('d-none');
            } else {
                // Show registration, hide signin
                signinForm.classList.add('d-none');
                registrationForm.classList.remove('d-none');
            }
        }
    </script>
</body>
</html>