CREATE TABLE `user` (
    id INT(11) AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) DEFAULT NULL,
    email VARCHAR(50) DEFAULT NULL,
    password VARCHAR(400) DEFAULT NULL,
    status enum('not_active','active') NOT NULL DEFAULT 'not_active',
    tokencode varchar(400) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `logs` (
	id INT(14) AUTO_INCREMENT PRIMARY KEY,
    user_id INT(14) NOT NULL,
    activity VARCHAR(50) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE `email_config` (
  `id` int(145) AUTO_INCREMENT PRIMARY KEY,
  `email` varchar(145) DEFAULT NULL,
  `password` varchar(145) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
);