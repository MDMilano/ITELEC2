<?php
    include_once 'config/settings-configuration.php';
    
    if(isset($_SESSION['adminSession'])){
        header("Location: dashboard/admin/");
        exit;
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="src/css/styles.css">
</head>
<body class="custom-bg d-flex align-items-center justify-content-center min-vh-100">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-12 col-md-6 col-lg-5 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white py-3">
                        <h4 class="card-title text-center mb-0">Forgot Password</h4>
                    </div>
                    
                    <div class="card-body p-4">
                        <form action="dashboard/admin/authentication/admin-class.php" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="mb-3">
                                <label for="email" class="form-label">Email Address</label>
                                <input type="email" class="form-control" id="email" name="email" placeholder="example@gmail.com">
                            </div>
                            
                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-primary py-2" name="btn-forgot-password">
                                    Send Reset Link
                                </button>
                            </div>
                        </form>
                    </div>
                    
                    <div class="card-footer bg-white py-3 text-center">
                        <p class="text-decoration-none form-links">Remember your password? <a class="text-decoration-none form-links" href="index.php">Sign in</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>