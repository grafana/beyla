-- Sakila Sample Database Data
-- Version 1.2

-- Copyright (c) 2006, 2019, Oracle and/or its affiliates.
-- All rights reserved.

-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are
-- met:

-- * Redistributions of source code must retain the above copyright notice,
--   this list of conditions and the following disclaimer.
-- * Redistributions in binary form must reproduce the above copyright
--   notice, this list of conditions and the following disclaimer in the
--   documentation and/or other materials provided with the distribution.
-- * Neither the name of Oracle nor the names of its contributors may be used
--   to endorse or promote products derived from this software without
--   specific prior written permission.

-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
-- IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
-- THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
-- PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
-- CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
-- EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
-- PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
-- PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
-- LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
-- NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-- SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SET NAMES utf8mb4;
SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';
SET @old_autocommit=@@autocommit;

USE sakila;

--
-- Dumping data for table actor
--

SET AUTOCOMMIT=0;
INSERT INTO actor VALUES (1,'PENELOPE','GUINESS','2006-02-15 04:34:33'),
(2,'NICK','WAHLBERG','2006-02-15 04:34:33'),
(3,'ED','CHASE','2006-02-15 04:34:33'),
(4,'JENNIFER','DAVIS','2006-02-15 04:34:33'),
(5,'JOHNNY','LOLLOBRIGIDA','2006-02-15 04:34:33'),
(6,'BETTE','NICHOLSON','2006-02-15 04:34:33'),
(7,'GRACE','MOSTEL','2006-02-15 04:34:33'),
(8,'MATTHEW','JOHANSSON','2006-02-15 04:34:33');
COMMIT;

--
-- Dumping data for table address
--

SET AUTOCOMMIT=0;
INSERT INTO `address` VALUES (1,'47 MySakila Drive',NULL,'Alberta',300,'','',/*!50705 0x0000000001010000003E0A325D63345CC0761FDB8D99D94840,*/'2014-09-25 22:30:27'),
(2,'28 MySQL Boulevard',NULL,'QLD',576,'','',/*!50705 0x0000000001010000008E10D4DF812463404EE08C5022A23BC0,*/'2014-09-25 22:30:09'),
(3,'23 Workhaven Lane',NULL,'Alberta',300,'','14033335568',/*!50705 0x000000000101000000CDC4196863345CC01DEE7E7099D94840,*/'2014-09-25 22:30:27'),
(4,'1411 Lillydale Drive',NULL,'QLD',576,'','6172235589',/*!50705 0x0000000001010000005B0DE4341F26634042D6AE6422A23BC0,*/'2014-09-25 22:30:09'),
(5,'1913 Hanoi Way','','Nagasaki',463,'35200','28303384290',/*!50705 0x00000000010100000028D1370E21376040ABB58BC45F944040,*/'2014-09-25 22:31:53');
COMMIT;

--
-- Dumping data for table category
--

SET AUTOCOMMIT=0;
INSERT INTO category VALUES (1,'Action','2006-02-15 04:46:27'),
(2,'Animation','2006-02-15 04:46:27'),
(3,'Children','2006-02-15 04:46:27'),
(4,'Classics','2006-02-15 04:46:27'),
(5,'Comedy','2006-02-15 04:46:27'),
(6,'Documentary','2006-02-15 04:46:27'),
(7,'Drama','2006-02-15 04:46:27'),
(8,'Family','2006-02-15 04:46:27'),
(9,'Foreign','2006-02-15 04:46:27'),
(10,'Games','2006-02-15 04:46:27'),
(11,'Horror','2006-02-15 04:46:27'),
(12,'Music','2006-02-15 04:46:27'),
(13,'New','2006-02-15 04:46:27'),
(14,'Sci-Fi','2006-02-15 04:46:27'),
(15,'Sports','2006-02-15 04:46:27'),
(16,'Travel','2006-02-15 04:46:27');
COMMIT;

--
-- Dumping data for table city
--

SET AUTOCOMMIT=0;
INSERT INTO city VALUES (1,'A Corua (La Corua)',87,'2006-02-15 04:45:25'),
(2,'Abha',82,'2006-02-15 04:45:25'),
(3,'Abu Dhabi',101,'2006-02-15 04:45:25'),
(4,'Acua',60,'2006-02-15 04:45:25'),
(5,'Adana',97,'2006-02-15 04:45:25'),
(6,'Addis Abeba',31,'2006-02-15 04:45:25');
COMMIT;

--
-- Dumping data for table country
--

SET AUTOCOMMIT=0;
INSERT INTO country VALUES (1,'Afghanistan','2006-02-15 04:44:00'),
(2,'Algeria','2006-02-15 04:44:00'),
(3,'American Samoa','2006-02-15 04:44:00'),
(4,'Angola','2006-02-15 04:44:00'),
(5,'Anguilla','2006-02-15 04:44:00'),
(6,'Argentina','2006-02-15 04:44:00'),
(7,'Armenia','2006-02-15 04:44:00');
COMMIT;

--
-- Dumping data for table customer
--

SET AUTOCOMMIT=0;
INSERT INTO customer VALUES (1,1,'MARY','SMITH','MARY.SMITH@sakilacustomer.org',5,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(2,1,'PATRICIA','JOHNSON','PATRICIA.JOHNSON@sakilacustomer.org',6,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(3,1,'LINDA','WILLIAMS','LINDA.WILLIAMS@sakilacustomer.org',7,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(4,2,'BARBARA','JONES','BARBARA.JONES@sakilacustomer.org',8,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(5,1,'ELIZABETH','BROWN','ELIZABETH.BROWN@sakilacustomer.org',9,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(6,2,'JENNIFER','DAVIS','JENNIFER.DAVIS@sakilacustomer.org',10,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(7,1,'MARIA','MILLER','MARIA.MILLER@sakilacustomer.org',11,1,'2006-02-14 22:04:36','2006-02-15 04:57:20'),
(8,2,'SUSAN','WILSON','SUSAN.WILSON@sakilacustomer.org',12,1,'2006-02-14 22:04:36','2006-02-15 04:57:20');
COMMIT;

--
-- Trigger to enforce create dates on INSERT
--

CREATE TRIGGER customer_create_date BEFORE INSERT ON customer
	FOR EACH ROW SET NEW.create_date = NOW();

--
-- Dumping data for table film
--

SET AUTOCOMMIT=0;
INSERT INTO film VALUES (1,'ACADEMY DINOSAUR','A Epic Drama of a Feminist And a Mad Scientist who must Battle a Teacher in The Canadian Rockies',2006,1,NULL,6,'0.99',86,'20.99','PG','Deleted Scenes,Behind the Scenes','2006-02-15 05:03:42'),
(2,'ACE GOLDFINGER','A Astounding Epistle of a Database Administrator And a Explorer who must Find a Car in Ancient China',2006,1,NULL,3,'4.99',48,'12.99','G','Trailers,Deleted Scenes','2006-02-15 05:03:42'),
(3,'ADAPTATION HOLES','A Astounding Reflection of a Lumberjack And a Car who must Sink a Lumberjack in A Baloon Factory',2006,1,NULL,7,'2.99',50,'18.99','NC-17','Trailers,Deleted Scenes','2006-02-15 05:03:42'),
(4,'AFFAIR PREJUDICE','A Fanciful Documentary of a Frisbee And a Lumberjack who must Chase a Monkey in A Shark Tank',2006,1,NULL,5,'2.99',117,'26.99','G','Commentaries,Behind the Scenes','2006-02-15 05:03:42'),
(5,'AFRICAN EGG','A Fast-Paced Documentary of a Pastry Chef And a Dentist who must Pursue a Forensic Psychologist in The Gulf of Mexico',2006,1,NULL,6,'2.99',130,'22.99','G','Deleted Scenes','2006-02-15 05:03:42'),
(6,'AGENT TRUMAN','A Intrepid Panorama of a Robot And a Boy who must Escape a Sumo Wrestler in Ancient China',2006,1,NULL,3,'2.99',169,'17.99','PG','Deleted Scenes','2006-02-15 05:03:42'),
(7,'AIRPLANE SIERRA','A Touching Saga of a Hunter And a Butler who must Discover a Butler in A Jet Boat',2006,1,NULL,6,'4.99',62,'28.99','PG-13','Trailers,Deleted Scenes','2006-02-15 05:03:42'),
(8,'AIRPORT POLLOCK','A Epic Tale of a Moose And a Girl who must Confront a Monkey in Ancient India',2006,1,NULL,6,'4.99',54,'15.99','R','Trailers','2006-02-15 05:03:42');
COMMIT;

--
-- Dumping data for table film_actor
--

SET AUTOCOMMIT=0;
INSERT INTO film_actor VALUES (1,1,'2006-02-15 05:05:03'),
(1,23,'2006-02-15 05:05:03'),
(1,25,'2006-02-15 05:05:03'),
(1,106,'2006-02-15 05:05:03'),
(1,140,'2006-02-15 05:05:03'),
(1,166,'2006-02-15 05:05:03'),
(1,277,'2006-02-15 05:05:03'),
(1,361,'2006-02-15 05:05:03'),
(1,438,'2006-02-15 05:05:03');
COMMIT;

--
-- Dumping data for table film_category
--

SET AUTOCOMMIT=0;
INSERT INTO film_category VALUES (1,6,'2006-02-15 05:07:09'),
(2,11,'2006-02-15 05:07:09'),
(3,6,'2006-02-15 05:07:09'),
(4,11,'2006-02-15 05:07:09'),
(5,8,'2006-02-15 05:07:09'),
(6,9,'2006-02-15 05:07:09'),
(7,5,'2006-02-15 05:07:09'),
(8,11,'2006-02-15 05:07:09');
COMMIT;

--
-- Dumping data for table language
--

SET AUTOCOMMIT=0;
INSERT INTO language VALUES (1,'English','2006-02-15 05:02:19'),
(2,'Italian','2006-02-15 05:02:19'),
(3,'Japanese','2006-02-15 05:02:19'),
(4,'Mandarin','2006-02-15 05:02:19'),
(5,'French','2006-02-15 05:02:19'),
(6,'German','2006-02-15 05:02:19');
COMMIT;

--
-- Dumping data for table payment
--

SET AUTOCOMMIT=0;
INSERT INTO payment VALUES (1,1,1,76,'2.99','2005-05-25 11:30:37','2006-02-15 22:12:30'),
(2,1,1,573,'0.99','2005-05-28 10:35:23','2006-02-15 22:12:30'),
(3,1,1,1185,'5.99','2005-06-15 00:54:12','2006-02-15 22:12:30'),
(4,1,2,1422,'0.99','2005-06-15 18:02:53','2006-02-15 22:12:30'),
(5,1,2,1476,'9.99','2005-06-15 21:08:46','2006-02-15 22:12:30'),
(6,1,1,1725,'4.99','2005-06-16 15:18:57','2006-02-15 22:12:30'),
(7,1,1,2308,'4.99','2005-06-18 08:41:48','2006-02-15 22:12:30'),
(8,1,2,2363,'0.99','2005-06-18 13:33:59','2006-02-15 22:12:30');
COMMIT;

--
-- Trigger to enforce payment_date during INSERT
--

CREATE TRIGGER payment_date BEFORE INSERT ON payment
	FOR EACH ROW SET NEW.payment_date = NOW();

--
-- Dumping data for table rental
--

SET AUTOCOMMIT=0;
INSERT INTO rental VALUES (1,'2005-05-24 22:53:30',367,130,'2005-05-26 22:04:30',1,'2006-02-15 21:30:53'),
(2,'2005-05-24 22:54:33',1525,459,'2005-05-28 19:40:33',1,'2006-02-15 21:30:53'),
(3,'2005-05-24 23:03:39',1711,408,'2005-06-01 22:12:39',1,'2006-02-15 21:30:53'),
(4,'2005-05-24 23:04:41',2452,333,'2005-06-03 01:43:41',2,'2006-02-15 21:30:53'),
(5,'2005-05-24 23:05:21',2079,222,'2005-06-02 04:33:21',1,'2006-02-15 21:30:53'),
(6,'2005-05-24 23:08:07',2792,549,'2005-05-27 01:32:07',1,'2006-02-15 21:30:53'),
(7,'2005-05-24 23:11:53',3995,269,'2005-05-29 20:34:53',2,'2006-02-15 21:30:53'),
(8,'2005-05-24 23:31:46',2346,239,'2005-05-27 23:33:46',2,'2006-02-15 21:30:53');
COMMIT;

--
-- Trigger to enforce rental_date on INSERT
--

CREATE TRIGGER rental_date BEFORE INSERT ON rental
	FOR EACH ROW SET NEW.rental_date = NOW();

--
-- Dumping data for table store
--

SET AUTOCOMMIT=0;
INSERT INTO store VALUES (1,1,1,'2006-02-15 04:57:12'),
(2,2,2,'2006-02-15 04:57:12');
COMMIT;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
SET autocommit=@old_autocommit;
