<?php

    // Define a class named Database to handle database connections.
    class Database
    {
        // Declare private properties for database connection details.
        private $host;
        private $db_name;
        private $username;
        private $password;
        // Declare a public property to hold the database connection.
        public $conn;

        // Constructor method to initialize database connection details.
        public function __construct()
        {
            // Check if the server is running on localhost or a specific IP address.
            if($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['SERVER_ADDR'] === '127.0.0.1' || $_SERVER['SERVER_NAME'] === '192.168.1.72'){
                // Set database connection details for the local environment.
                $this->host = "localhost";
                $this->db_name = "itelec2";
                $this->username = "root";
                $this->password = "";
            }
            else{
                // Set database connection details for a production environment.
                $this->host = "localhost";
                $this->db_name = "";
                $this->username = "";
                $this->password = "";
            }
        }

        // Method to establish a database connection.
        public function dbConnection()
        {
            // Initialize the connection property to null.
            $this->conn = null;
            try {
                // Attempt to create a new PDO connection using the provided details.
                $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
                // Set the PDO error mode to exception for better error handling.
                $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            } catch (PDOException $exception) 
            {
                // Catch any connection errors and display the error message.
                echo "Connection error: " . $exception->getMessage();
            }
            // Return the database connection object.
            return $this->conn;
        }
    }
?>