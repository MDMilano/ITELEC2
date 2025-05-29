<?php

require_once 'authentication/admin-class.php';

$admin = new ADMIN();

if(!isset($_SESSION['adminSession'])){
    echo "<script>alert('Please logged in!'); window.location.href='../../';</script>";
    exit;
}

$stmt = $admin->runQuery("SELECT * FROM user WHERE id = :id");
$stmt->execute(array(":id"=>$_SESSION['adminSession']));
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
</head>
<body class="bg-light">
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
        <div class="container">
            <a class="navbar-brand" href="#">Admin Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Users</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Settings</a>
                    </li>
                </ul>
                <div class="d-flex align-items-center">
                    <span class="text-white me-3">
                        <i class="bi bi-person-circle me-1"></i>
                        <?php echo htmlspecialchars($user_data['email']); ?>
                    </span>
                    <a href="authentication/admin-class.php?admin_signout" class="btn btn-light btn-sm">
                        <i class="bi bi-box-arrow-right me-1"></i>Sign Out
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container py-4">
        <!-- Welcome Header -->
        <div class="row mb-4">
            <div class="col">
                <div class="card border-0 shadow-sm">
                    <div class="card-body p-4">
                        <h2 class="card-title">Welcome, Admin!</h2>
                        <p class="card-text text-muted">
                            You are logged in as <strong><?php echo htmlspecialchars($user_data['email']); ?></strong>
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Dashboard Stats -->
        <div class="row g-4 mb-4">
            <!-- Stat Card 1 -->
            <div class="col-md-4">
                <div class="card border-0 shadow-sm h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="text-muted mb-1">Total Users</h6>
                                <h3 class="mb-0">1,250</h3>
                            </div>
                            <div class="bg-primary bg-opacity-10 p-2 rounded">
                                <i class="bi bi-people text-primary fs-4"></i>
                            </div>
                        </div>
                        <div class="mt-3">
                            <span class="text-success">
                                <i class="bi bi-arrow-up"></i> 12%
                            </span>
                            <span class="text-muted ms-2">Since last month</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Stat Card 2 -->
            <div class="col-md-4">
                <div class="card border-0 shadow-sm h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="text-muted mb-1">New Registrations</h6>
                                <h3 class="mb-0">85</h3>
                            </div>
                            <div class="bg-success bg-opacity-10 p-2 rounded">
                                <i class="bi bi-person-plus text-success fs-4"></i>
                            </div>
                        </div>
                        <div class="mt-3">
                            <span class="text-success">
                                <i class="bi bi-arrow-up"></i> 5.3%
                            </span>
                            <span class="text-muted ms-2">Since last week</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Stat Card 3 -->
            <div class="col-md-4">
                <div class="card border-0 shadow-sm h-100">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="text-muted mb-1">Active Sessions</h6>
                                <h3 class="mb-0">42</h3>
                            </div>
                            <div class="bg-info bg-opacity-10 p-2 rounded">
                                <i class="bi bi-activity text-info fs-4"></i>
                            </div>
                        </div>
                        <div class="mt-3">
                            <span class="text-danger">
                                <i class="bi bi-arrow-down"></i> 2.8%
                            </span>
                            <span class="text-muted ms-2">Since yesterday</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="row">
            <div class="col-lg-8 mb-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white py-3">
                        <h5 class="card-title mb-0">Recent Activity</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="list-group list-group-flush">
                            <div class="list-group-item py-3">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1">New user registered</h6>
                                    <small class="text-muted">3 minutes ago</small>
                                </div>
                                <p class="mb-1 text-muted">john.doe@example.com created an account</p>
                            </div>
                            <div class="list-group-item py-3">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1">System update completed</h6>
                                    <small class="text-muted">1 hour ago</small>
                                </div>
                                <p class="mb-1 text-muted">The system was updated to version 2.4.0</p>
                            </div>
                            <div class="list-group-item py-3">
                                <div class="d-flex w-100 justify-content-between">
                                    <h6 class="mb-1">Database backup</h6>
                                    <small class="text-muted">5 hours ago</small>
                                </div>
                                <p class="mb-1 text-muted">Automatic database backup completed successfully</p>
                            </div>
                        </div>
                    </div>
                    <div class="card-footer bg-white text-center">
                        <a href="#" class="btn btn-sm btn-outline-primary">View All Activity</a>
                    </div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="col-lg-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white py-3">
                        <h5 class="card-title mb-0">Quick Actions</h5>
                    </div>
                    <div class="card-body">
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-primary">
                                <i class="bi bi-person-plus me-2"></i>Add New User
                            </button>
                            <button class="btn btn-outline-success">
                                <i class="bi bi-gear me-2"></i>System Settings
                            </button>
                            <button class="btn btn-outline-info">
                                <i class="bi bi-file-earmark-text me-2"></i>Generate Report
                            </button>
                            <button class="btn btn-outline-warning">
                                <i class="bi bi-shield-lock me-2"></i>Security Audit
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white py-4 mt-auto border-top">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center">
                <span class="text-muted">© 2023 Admin Dashboard</span>
                <div>
                    <a href="#" class="text-muted text-decoration-none me-3">Privacy Policy</a>
                    <a href="#" class="text-muted text-decoration-none">Terms of Service</a>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>