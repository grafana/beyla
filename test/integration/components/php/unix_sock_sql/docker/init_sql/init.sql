CREATE DATABASE IF NOT EXISTS `testdb` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
GO
USE `testdb`;
GO
CREATE TABLE IF NOT EXISTS `accounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `address` varchar(255) NOT NULL DEFAULT '',
   PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
GO
INSERT INTO `accounts` (name, address) VALUES ('My Company', '1234 Some Address, Some Town, Canada'), ('Other Company', '234 Some Street, Another Town, Spain'), ('Another Company', '456 Another Street, Large Town, Germany');

