<?php
    include_once 'config/settings-configuration.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify OTP</title>
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
                        <h4 class="card-title text-center mb-0">Verify OTP</h4>
                    </div>
                    
                    <div class="card-body p-4">
                        <form action="dashboard/admin/authentication/admin-class.php" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="mb-3">
                                <label for="otp" class="form-label">Enter the OTP sent to your email</label>
                                <input type="number" class="form-control" id="otp" name="otp" placeholder="Enter OTP">
                            </div>
                            
                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-primary py-2" name="btn-verify">
                                    Submit
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>