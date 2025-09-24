<?php
session_start();
require '../config.php';

// ✅ Only allow clinic_owner
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'clinic_owner') {
    header("Location: ../login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$name = htmlspecialchars($_SESSION['name'] ?? '');

// ✅ Get user info
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

$profilePic = !empty($user['profile_picture']) ? $user['profile_picture'] : 'default.png';

// ✅ Get clinic
$stmt = $pdo->prepare("SELECT clinic_id FROM clinics WHERE user_id = ?");
$stmt->execute([$user_id]);
$clinic = $stmt->fetch();

$staffMembers = [];

if (!$clinic) {
    $_SESSION['swal'] = [
        'icon' => 'error',
        'title' => 'No Clinic Found',
        'text' => 'You must register your clinic first before adding staff.'
    ];
} else {
    $clinic_id = $clinic['clinic_id'];

    // ✅ Handle Add / Update Staff
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Add Staff
        if (isset($_POST['add_staff'])) {
            $staff_name   = trim($_POST['name']);
            $staff_role   = $_POST['role'];
            $contact      = trim($_POST['contact_number']);
            $email        = trim($_POST['email']);
            $password_raw = $_POST['password'];

            $errors = [];
            if (strlen($staff_name) < 3) $errors[] = "Name must be at least 3 characters.";
            if (!in_array($staff_role, ['staff', 'doctor'])) $errors[] = "Invalid role.";
            if (!preg_match('/^09\d{9}$/', $contact)) $errors[] = "Invalid contact number.";
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email.";
            if (strlen($password_raw) < 6 || !preg_match('/[A-Za-z]/', $password_raw) || !preg_match('/[0-9]/', $password_raw)) {
                $errors[] = "Password must be at least 6 chars with letters & numbers.";
            }

            // Profile pic
            $fileName = null;
            if (!empty($_FILES['profile_picture']['name'])) {
                $targetDir = "../uploads/profiles/";
                if (!is_dir($targetDir)) mkdir($targetDir, 0777, true);
                $fileName = time() . "_" . basename($_FILES["profile_picture"]["name"]);
                move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $targetDir . $fileName);
            }

            if (empty($errors)) {
                $password = password_hash($password_raw, PASSWORD_DEFAULT);
                $check = $pdo->prepare("SELECT 1 FROM staff WHERE email=?");
                $check->execute([$email]);
                if ($check->fetch()) {
                    $_SESSION['swal'] = [
                        'icon' => 'error',
                        'title' => 'Duplicate Email',
                        'text' => 'Email already exists.'
                    ];
                } else {
                    $stmt = $pdo->prepare("INSERT INTO staff (clinic_id,name,role,contact_number,email,password,profile_picture) 
                                           VALUES (?,?,?,?,?,?,?)");
                    $stmt->execute([$clinic_id, $staff_name, $staff_role, $contact, $email, $password, $fileName]);
                    $_SESSION['swal'] = [
                        'icon' => 'success',
                        'title' => 'Staff Added',
                        'text' => 'Staff added successfully!'
                    ];
                }
            } else {
                $_SESSION['swal'] = [
                    'icon' => 'error',
                    'title' => 'Validation Error',
                    'text' => implode(" | ", $errors)
                ];
            }

            header("Location: manage_staff.php");
            exit;
        }

        // Update Staff
        if (isset($_POST['update_staff'])) {
            $id         = $_POST['staff_id'];
            $staff_name = trim($_POST['name']);
            $staff_role = $_POST['role'];
            $contact    = trim($_POST['contact_number']);
            $email      = trim($_POST['email']);
            $password   = $_POST['password'];

            $sql = "UPDATE staff SET name=?,role=?,contact_number=?,email=?";
            $params = [$staff_name, $staff_role, $contact, $email];

            if (!empty($password)) {
                $sql .= ", password=?";
                $params[] = password_hash($password, PASSWORD_DEFAULT);
            }

            if (!empty($_FILES['profile_picture']['name'])) {
                $targetDir = "../uploads/profiles/";
                if (!is_dir($targetDir)) mkdir($targetDir, 0777, true);
                $fileName = time() . "_" . basename($_FILES["profile_picture"]["name"]);
                move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $targetDir . $fileName);
                $sql .= ", profile_picture=?";
                $params[] = $fileName;
            }

            $sql .= " WHERE staff_id=? AND clinic_id=?";
            $params[] = $id;
            $params[] = $clinic_id;

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

            $_SESSION['swal'] = [
                'icon' => 'success',
                'title' => 'Staff Updated',
                'text' => 'Staff updated successfully!'
            ];

            header("Location: manage_staff.php");
            exit;
        }
    }

    // ✅ Delete Staff
    if (isset($_GET['delete'])) {
        $id = (int)$_GET['delete'];
        $stmt = $pdo->prepare("DELETE FROM staff WHERE staff_id=? AND clinic_id=?");
        $stmt->execute([$id, $clinic_id]);
        $_SESSION['swal'] = [
            'icon' => 'success',
            'title' => 'Staff Deleted',
            'text' => 'Staff deleted successfully!'
        ];
        header("Location: manage_staff.php");
        exit;
    }

    // ✅ Fetch staff list
    $staffList = $pdo->prepare("SELECT * FROM staff WHERE clinic_id=?");
    $staffList->execute([$clinic_id]);
    $staffMembers = $staffList->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Manage Staff - VetCareSys</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body { background-color: #f4f6f9; }
        .card { border: none; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); transition: transform 0.2s ease; }
        .card:hover { transform: translateY(-3px); }
    </style>
</head>

<body class="bg-light">

<!-- ✅ Navbar -->
<nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php">VetCareSys</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="topNav">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                <li class="nav-item"><a href="manage_clinic.php" class="nav-link text-white">Manage Clinic</a></li>
                <li class="nav-item"><a href="manage_staff.php" class="nav-link text-white">Manage Staff</a></li>
                <li class="nav-item"><a href="manage_clinic_schedules.php" class="nav-link text-white">Manage Schedules</a></li>
                <li class="nav-item"><a href="manage_services.php" class="nav-link text-white">Manage Services</a></li>
                <li class="nav-item"><a href="manage_forms.php" class="nav-link text-white">Manage Forms</a></li>
            </ul>
            <div class="dropdown">
                <a href="#" class="d-flex align-items-center text-white text-decoration-none dropdown-toggle"
                   id="dropdownUser" data-bs-toggle="dropdown" aria-expanded="false">
                    <img src="../uploads/profiles/<?= htmlspecialchars($profilePic) ?>" alt="Profile" width="32" height="32" class="rounded-circle me-2">
                    <strong><?= htmlspecialchars($name) ?></strong>
                </a>
                <ul class="dropdown-menu dropdown-menu-end shadow" aria-labelledby="dropdownUser">
                    <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#profileModal">View Profile</a></li>
                    <li><a class="dropdown-item" href="manage_clinic_details.php">Update Clinic Info</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li>
                        <form method="POST" action="logout.php" class="m-0">
                            <button class="dropdown-item text-danger" type="submit"><i class="bi bi-box-arrow-right"></i> Logout</button>
                        </form>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</nav>

<div class="container py-4">
    <!-- Add Staff Form -->
    <div class="card shadow mb-4">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="bi bi-person-plus-fill"></i> Add New Staff Member</h5>
        </div>
        <div class="card-body">
            <form method="POST" class="row g-3" enctype="multipart/form-data">
                <input type="hidden" name="add_staff" value="1">
                <div class="col-md-6">
                    <label class="form-label">Staff Name</label>
                    <input type="text" name="name" class="form-control" placeholder="Enter full name" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Role</label>
                    <select name="role" class="form-select" required>
                        <option value="staff">Staff</option>
                        <option value="doctor">Doctor</option>
                    </select>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Contact Number</label>
                    <input type="text" name="contact_number" class="form-control" placeholder="09XXXXXXXXX" maxlength="11" inputmode="numeric" pattern="^09\d{9}$" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Email Address</label>
                    <input type="email" name="email" class="form-control" placeholder="example@email.com" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" placeholder="Enter password" minlength="6" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Profile Picture</label>
                    <input type="file" name="profile_picture" class="form-control">
                </div>
                <div class="col-md-12">
                    <button type="submit" class="btn btn-success"><i class="bi bi-check-lg"></i> Add Staff</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Staff List -->
    <div class="card shadow-lg border-0 rounded-3">
        <div class="card-header bg-gradient bg-secondary text-white">
            <h5 class="mb-0"><i class="bi bi-people-fill me-2"></i> Registered Staff Members</h5>
        </div>
        <div class="card-body p-0">
            <?php if (count($staffMembers) > 0): ?>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="table-light">
                        <tr>
                            <th class="px-4">Name</th>
                            <th>Role</th>
                            <th>Contact</th>
                            <th>Email</th>
                            <th class="text-center">Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($staffMembers as $staff): ?>
                            <tr>
                                <td class="fw-semibold text-dark px-4">
                                    <img src="../uploads/profiles/<?= !empty($staff['profile_picture']) ? htmlspecialchars($staff['profile_picture']) : 'default.png' ?>" width="32" height="32" class="rounded-circle me-2" style="object-fit: cover;">
                                    <?= htmlspecialchars($staff['name']) ?>
                                </td>
                                <td>
                                    <?php if ($staff['role'] === 'doctor'): ?>
                                        <span class="badge bg-info px-3 py-2"><i class="bi bi-stethoscope me-1"></i> Doctor</span>
                                    <?php else: ?>
                                        <span class="badge bg-warning text-dark px-3 py-2"><i class="bi bi-people-fill me-1"></i> Staff</span>
                                    <?php endif; ?>
                                </td>
                                <td class="text-muted"><i class="bi bi-telephone me-2 text-success"></i><?= htmlspecialchars($staff['contact_number']) ?></td>
                                <td class="text-muted"><i class="bi bi-envelope-at me-2 text-secondary"></i><?= htmlspecialchars($staff['email']) ?></td>
                                <td class="text-center">
                                    <div class="d-inline-flex gap-2">
                                        <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editStaffModal<?= $staff['staff_id'] ?>"><i class="bi bi-pencil-square me-1"></i> Edit</button>
                                        <a href="manage_staff.php?delete=<?= $staff['staff_id'] ?>" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this staff member?');"><i class="bi bi-trash me-1"></i> Delete</a>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="p-3 mb-0 text-center text-muted">No staff registered yet.</p>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Edit Staff Modals -->
<?php foreach ($staffMembers as $staff): ?>
<div class="modal fade" id="editStaffModal<?= $staff['staff_id'] ?>" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="update_staff" value="1">
                <input type="hidden" name="staff_id" value="<?= $staff['staff_id'] ?>">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title">Edit Staff</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3"><label>Name</label><input type="text" name="name" class="form-control" value="<?= htmlspecialchars($staff['name']) ?>" required></div>
                    <div class="mb-3"><label>Role</label>
                        <select name="role" class="form-select" required>
                            <option value="staff" <?= $staff['role'] === 'staff' ? 'selected' : '' ?>>Staff</option>
                            <option value="doctor" <?= $staff['role'] === 'doctor' ? 'selected' : '' ?>>Doctor</option>
                        </select>
                    </div>
                    <div class="mb-3"><label>Contact Number</label><input type="text" name="contact_number" class="form-control" value="<?= htmlspecialchars($staff['contact_number']) ?>" required></div>
                    <div class="mb-3"><label>Email</label><input type="email" name="email" class="form-control" value="<?= htmlspecialchars($staff['email']) ?>" required></div>
                    <div class="mb-3"><label>New Password (leave blank to keep)</label><input type="password" name="password" class="form-control"></div>
                    <div class="mb-3"><label>Profile Picture</label><input type="file" name="profile_picture" class="form-control"></div>
                </div>
                <div class="modal-footer"><button type="submit" class="btn btn-success">Save Changes</button></div>
            </form>
        </div>
    </div>
</div>
<?php endforeach; ?>

<?php if (isset($_SESSION['swal'])): ?>
<script>
Swal.fire({
    icon: '<?= $_SESSION['swal']['icon'] ?>',
    title: '<?= $_SESSION['swal']['title'] ?>',
    text: '<?= $_SESSION['swal']['text'] ?>',
    timer: 2000,
    showConfirmButton: false
});
</script>
<?php unset($_SESSION['swal']); endif; ?>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
