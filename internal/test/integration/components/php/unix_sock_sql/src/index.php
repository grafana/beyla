<?php

echo "Hello world! from php-fpm";

$servername = "mysql";
$username = "root";
$password = "test";
$database = "testdb";

$conn = "";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$database", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    echo "Error: " . $e->getMessage();
    die;
}

$stmt = $conn->query("SELECT * FROM accounts")->fetchAll();
print_r($stmt);

?>
<!DOCTYPE html>
<html>
<body>

<h1>Hello World!</h1>

</body>
</html>

