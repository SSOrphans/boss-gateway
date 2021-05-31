create schema if not exists boss;

create table if not exists boss.user (
   id 			INT				NOT NULL AUTO_INCREMENT UNIQUE,
   type_id 		TINYINT 		NOT NULL,
   branch_id 	INT 			NOT NULL,
   username 	VARCHAR(16) 	NOT NULL UNIQUE,
   email 		VARCHAR(128) 	NOT NULL UNIQUE,
   password 	CHAR(64) 		NOT NULL,
   created 		BIGINT 			NOT NULL,
   deleted 		BIGINT,
   enabled 		BIT 			NOT NULL,
   locked 		BIT 			NOT NULL,
   PRIMARY KEY 	(id)
);

create table if not exists boss.account_holder
(
  user_id		INT UNSIGNED	NOT NULL,
  full_name		VARCHAR(64)		NOT NULL,
  dob			DATE			NOT NULL,
  ssn			CHAR(64)		NOT NULL,
  address		CHAR(255)		NOT NULL,
  city			CHAR(64) 		NOT NULL,
  state			CHAR(32)		NOT NULL,
  zip			INT				NOT NULL,
  phone			CHAR(16)		NOT NULL,
  
  PRIMARY KEY	(user_id),
  FOREIGN KEY	(user_id) REFERENCES boss.user (id)
);

create table if not exists boss.confirmation
(
    id                INT      NOT NULL AUTO_INCREMENT UNIQUE,
    type_id           TINYINT  NOT NULL,
    confirmable_id    INT      NOT NULL,
    confirmation_hash CHAR(36) NOT NULL UNIQUE,
    good_until        BIGINT   NOT NULL
);