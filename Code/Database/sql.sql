/*
SQLyog Enterprise - MySQL GUI v6.56
MySQL - 5.5.5-10.4.21-MariaDB : Database - cloudsecurestoragemechanism
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

CREATE DATABASE /*!32312 IF NOT EXISTS*/`cloudsecurestoragemechanism` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;

USE `cloudsecurestoragemechanism`;

/*Table structure for table `serverone` */

DROP TABLE IF EXISTS `serverone`;

CREATE TABLE `serverone` (
  `id` int(200) NOT NULL AUTO_INCREMENT,
  `Filename` varchar(200) DEFAULT NULL,
  `File` varchar(200) DEFAULT NULL,
  `Fileencdata` longblob DEFAULT NULL,
  `Trapdoor` varchar(200) DEFAULT NULL,
  `OwnerType` varchar(200) DEFAULT 'Sender',
  `Userid` varchar(200) DEFAULT NULL,
  `status` varchar(100) DEFAULT 'pending',
  `Attack` varchar(100) DEFAULT 'perform',
  `Filerequest` varchar(100) DEFAULT 'pending',
  `Receiver` varchar(100) DEFAULT 'none',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

/*Data for the table `serverone` */

/*Table structure for table `serverthree` */

DROP TABLE IF EXISTS `serverthree`;

CREATE TABLE `serverthree` (
  `id` int(200) NOT NULL AUTO_INCREMENT,
  `Filename` varchar(200) DEFAULT NULL,
  `File` varchar(200) DEFAULT NULL,
  `Fileencdata` longblob DEFAULT NULL,
  `Trapdoor` varchar(100) DEFAULT NULL,
  `OwnerType` varchar(100) DEFAULT 'sender',
  `Userid` varchar(100) DEFAULT NULL,
  `status` varchar(100) DEFAULT 'pending',
  `Attack` varchar(100) DEFAULT 'perform',
  `Filerequest` varchar(100) DEFAULT 'pending',
  `Receiver` varchar(100) DEFAULT 'none',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

/*Data for the table `serverthree` */

insert  into `serverthree`(`id`,`Filename`,`File`,`Fileencdata`,`Trapdoor`,`OwnerType`,`Userid`,`status`,`Attack`,`Filerequest`,`Receiver`) values (1,'textfile.txt','hi hello how are you','.πΩﬂnJY¢Xq7JæÜ∂∂°{^ÑÁ>Aﬂ G','e620647e9c5a8d3d9685cb72f45a46a034b297ea','sender','1','pending','perform','pending','none');

/*Table structure for table `servertwo` */

DROP TABLE IF EXISTS `servertwo`;

CREATE TABLE `servertwo` (
  `id` int(200) NOT NULL AUTO_INCREMENT,
  `Filename` varchar(200) DEFAULT NULL,
  `File` varchar(200) DEFAULT NULL,
  `Fileencdata` longblob DEFAULT NULL,
  `Trapdoor` varchar(200) DEFAULT NULL,
  `OwnerType` varchar(200) DEFAULT 'sender',
  `userid` varchar(200) DEFAULT NULL,
  `status` varchar(100) DEFAULT 'pending',
  `Attack` varchar(100) DEFAULT 'perform',
  `Filerequest` varchar(100) DEFAULT 'pending',
  `Receiver` varchar(100) DEFAULT 'none',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

/*Data for the table `servertwo` */

insert  into `servertwo`(`id`,`Filename`,`File`,`Fileencdata`,`Trapdoor`,`OwnerType`,`userid`,`status`,`Attack`,`Filerequest`,`Receiver`) values (1,'hello.txt','hello sir\r\n','¡ıâd5¢)¿$e™ÀKÒ„ù','c612a59368c1b6cc6ba6cb4f0fc898e5675f9d6e','sender','1','pending','perform','accept','receiver@gmail.com');

/*Table structure for table `userregistration` */

DROP TABLE IF EXISTS `userregistration`;

CREATE TABLE `userregistration` (
  `id` int(200) NOT NULL AUTO_INCREMENT,
  `usertype` varchar(200) DEFAULT NULL,
  `name` varchar(200) DEFAULT NULL,
  `passcode` varchar(200) DEFAULT NULL,
  `dob` varchar(200) DEFAULT NULL,
  `gender` varchar(200) DEFAULT NULL,
  `contact` varchar(200) DEFAULT NULL,
  `email` varchar(200) DEFAULT NULL,
  `address` varchar(200) DEFAULT NULL,
  `pincode` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4;

/*Data for the table `userregistration` */

insert  into `userregistration`(`id`,`usertype`,`name`,`passcode`,`dob`,`gender`,`contact`,`email`,`address`,`pincode`) values (1,'sender','sender','sender','12-06-1998','male','7894561231','sender@gmail.com','KADAPA','524854'),(2,'receiver','receiver','receiver','19-06-1997','female','6753428910','receiver@gmail.com','Mumbai','125874');

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
