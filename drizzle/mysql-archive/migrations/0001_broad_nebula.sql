CREATE TABLE `bookingItems` (
	`id` int AUTO_INCREMENT NOT NULL,
	`bookingId` int NOT NULL,
	`inventoryId` int NOT NULL,
	`unitPrice` decimal(10,2) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `bookingItems_id` PRIMARY KEY(`id`),
	CONSTRAINT `booking_items_unique_idx` UNIQUE(`bookingId`,`inventoryId`)
);
--> statement-breakpoint
CREATE TABLE `bookings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`eventId` int NOT NULL,
	`reservationId` int NOT NULL,
	`status` enum('PENDING','CONFIRMED','CANCELLED') NOT NULL DEFAULT 'PENDING',
	`totalAmount` decimal(10,2) NOT NULL,
	`confirmedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bookings_id` PRIMARY KEY(`id`),
	CONSTRAINT `bookings_reservationId_unique` UNIQUE(`reservationId`)
);
--> statement-breakpoint
CREATE TABLE `events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`venueId` int NOT NULL,
	`name` varchar(180) NOT NULL,
	`slug` varchar(180) NOT NULL,
	`description` text NOT NULL,
	`startTime` timestamp NOT NULL,
	`endTime` timestamp NOT NULL,
	`status` enum('DRAFT','PUBLISHED','SOLD_OUT','CANCELLED','COMPLETED') NOT NULL DEFAULT 'DRAFT',
	`maxTicketsPerUser` int NOT NULL DEFAULT 4,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `events_id` PRIMARY KEY(`id`),
	CONSTRAINT `events_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE TABLE `idempotencyKeys` (
	`id` int AUTO_INCREMENT NOT NULL,
	`key` varchar(128) NOT NULL,
	`userId` int NOT NULL,
	`operation` varchar(80) NOT NULL,
	`requestHash` varchar(128) NOT NULL,
	`responseJson` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `idempotencyKeys_id` PRIMARY KEY(`id`),
	CONSTRAINT `idempotency_key_operation_idx` UNIQUE(`key`,`userId`,`operation`)
);
--> statement-breakpoint
CREATE TABLE `inventory` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eventId` int NOT NULL,
	`seatId` int NOT NULL,
	`status` enum('AVAILABLE','RESERVED','SOLD','CANCELLED') NOT NULL DEFAULT 'AVAILABLE',
	`reservationId` int,
	`bookingId` int,
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `inventory_id` PRIMARY KEY(`id`),
	CONSTRAINT `inventory_event_seat_idx` UNIQUE(`eventId`,`seatId`)
);
--> statement-breakpoint
CREATE TABLE `payments` (
	`id` int AUTO_INCREMENT NOT NULL,
	`bookingId` int NOT NULL,
	`reservationId` int NOT NULL,
	`provider` varchar(48) NOT NULL DEFAULT 'mock',
	`providerPaymentId` varchar(128) NOT NULL,
	`amount` decimal(10,2) NOT NULL,
	`status` enum('PENDING','SUCCEEDED','FAILED','REFUNDED') NOT NULL DEFAULT 'PENDING',
	`idempotencyKey` varchar(128),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `payments_id` PRIMARY KEY(`id`),
	CONSTRAINT `payments_providerPaymentId_unique` UNIQUE(`providerPaymentId`),
	CONSTRAINT `payments_idempotency_idx` UNIQUE(`idempotencyKey`)
);
--> statement-breakpoint
CREATE TABLE `reservationItems` (
	`id` int AUTO_INCREMENT NOT NULL,
	`reservationId` int NOT NULL,
	`inventoryId` int NOT NULL,
	`unitPrice` decimal(10,2) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `reservationItems_id` PRIMARY KEY(`id`),
	CONSTRAINT `reservation_items_unique_idx` UNIQUE(`reservationId`,`inventoryId`)
);
--> statement-breakpoint
CREATE TABLE `reservations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`eventId` int NOT NULL,
	`status` enum('RESERVED','PAYMENT_PENDING','CONFIRMED','EXPIRED','PAYMENT_FAILED','CANCELLED') NOT NULL DEFAULT 'RESERVED',
	`expiresAt` timestamp NOT NULL,
	`totalAmount` decimal(10,2) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `reservations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `seats` (
	`id` int AUTO_INCREMENT NOT NULL,
	`venueId` int NOT NULL,
	`section` varchar(32) NOT NULL,
	`row` varchar(32) NOT NULL,
	`number` int NOT NULL,
	`seatType` enum('VIP','PREMIUM','STANDARD') NOT NULL DEFAULT 'STANDARD',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `seats_id` PRIMARY KEY(`id`),
	CONSTRAINT `seats_venue_identity_idx` UNIQUE(`venueId`,`section`,`row`,`number`)
);
--> statement-breakpoint
CREATE TABLE `ticketTypes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eventId` int NOT NULL,
	`name` varchar(80) NOT NULL,
	`price` decimal(10,2) NOT NULL,
	`quantity` int NOT NULL,
	`maxPerUser` int NOT NULL DEFAULT 4,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ticketTypes_id` PRIMARY KEY(`id`),
	CONSTRAINT `ticket_types_event_name_idx` UNIQUE(`eventId`,`name`)
);
--> statement-breakpoint
CREATE TABLE `tickets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`bookingId` int NOT NULL,
	`userId` int NOT NULL,
	`eventId` int NOT NULL,
	`inventoryId` int NOT NULL,
	`publicCode` varchar(64) NOT NULL,
	`status` enum('VALID','CANCELLED') NOT NULL DEFAULT 'VALID',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `tickets_id` PRIMARY KEY(`id`),
	CONSTRAINT `tickets_publicCode_unique` UNIQUE(`publicCode`)
);
--> statement-breakpoint
CREATE TABLE `venues` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(160) NOT NULL,
	`address` varchar(255) NOT NULL,
	`capacity` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `venues_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `bookingItems` ADD CONSTRAINT `bookingItems_bookingId_bookings_id_fk` FOREIGN KEY (`bookingId`) REFERENCES `bookings`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `bookingItems` ADD CONSTRAINT `bookingItems_inventoryId_inventory_id_fk` FOREIGN KEY (`inventoryId`) REFERENCES `inventory`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `bookings` ADD CONSTRAINT `bookings_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `bookings` ADD CONSTRAINT `bookings_eventId_events_id_fk` FOREIGN KEY (`eventId`) REFERENCES `events`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `bookings` ADD CONSTRAINT `bookings_reservationId_reservations_id_fk` FOREIGN KEY (`reservationId`) REFERENCES `reservations`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `events` ADD CONSTRAINT `events_venueId_venues_id_fk` FOREIGN KEY (`venueId`) REFERENCES `venues`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `idempotencyKeys` ADD CONSTRAINT `idempotencyKeys_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `inventory` ADD CONSTRAINT `inventory_eventId_events_id_fk` FOREIGN KEY (`eventId`) REFERENCES `events`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `inventory` ADD CONSTRAINT `inventory_seatId_seats_id_fk` FOREIGN KEY (`seatId`) REFERENCES `seats`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `payments` ADD CONSTRAINT `payments_bookingId_bookings_id_fk` FOREIGN KEY (`bookingId`) REFERENCES `bookings`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `payments` ADD CONSTRAINT `payments_reservationId_reservations_id_fk` FOREIGN KEY (`reservationId`) REFERENCES `reservations`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reservationItems` ADD CONSTRAINT `reservationItems_reservationId_reservations_id_fk` FOREIGN KEY (`reservationId`) REFERENCES `reservations`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reservationItems` ADD CONSTRAINT `reservationItems_inventoryId_inventory_id_fk` FOREIGN KEY (`inventoryId`) REFERENCES `inventory`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reservations` ADD CONSTRAINT `reservations_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `reservations` ADD CONSTRAINT `reservations_eventId_events_id_fk` FOREIGN KEY (`eventId`) REFERENCES `events`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `seats` ADD CONSTRAINT `seats_venueId_venues_id_fk` FOREIGN KEY (`venueId`) REFERENCES `venues`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `ticketTypes` ADD CONSTRAINT `ticketTypes_eventId_events_id_fk` FOREIGN KEY (`eventId`) REFERENCES `events`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `tickets` ADD CONSTRAINT `tickets_bookingId_bookings_id_fk` FOREIGN KEY (`bookingId`) REFERENCES `bookings`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `tickets` ADD CONSTRAINT `tickets_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `tickets` ADD CONSTRAINT `tickets_eventId_events_id_fk` FOREIGN KEY (`eventId`) REFERENCES `events`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `tickets` ADD CONSTRAINT `tickets_inventoryId_inventory_id_fk` FOREIGN KEY (`inventoryId`) REFERENCES `inventory`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `booking_items_booking_idx` ON `bookingItems` (`bookingId`);--> statement-breakpoint
CREATE INDEX `bookings_user_idx` ON `bookings` (`userId`);--> statement-breakpoint
CREATE INDEX `bookings_event_idx` ON `bookings` (`eventId`);--> statement-breakpoint
CREATE INDEX `events_status_idx` ON `events` (`status`);--> statement-breakpoint
CREATE INDEX `events_start_time_idx` ON `events` (`startTime`);--> statement-breakpoint
CREATE INDEX `idempotency_user_idx` ON `idempotencyKeys` (`userId`);--> statement-breakpoint
CREATE INDEX `inventory_status_idx` ON `inventory` (`eventId`,`status`);--> statement-breakpoint
CREATE INDEX `inventory_reservation_idx` ON `inventory` (`reservationId`);--> statement-breakpoint
CREATE INDEX `payments_booking_idx` ON `payments` (`bookingId`);--> statement-breakpoint
CREATE INDEX `reservation_items_reservation_idx` ON `reservationItems` (`reservationId`);--> statement-breakpoint
CREATE INDEX `reservations_user_idx` ON `reservations` (`userId`);--> statement-breakpoint
CREATE INDEX `reservations_event_idx` ON `reservations` (`eventId`);--> statement-breakpoint
CREATE INDEX `reservations_status_idx` ON `reservations` (`status`);--> statement-breakpoint
CREATE INDEX `reservations_expiry_idx` ON `reservations` (`expiresAt`);--> statement-breakpoint
CREATE INDEX `seats_venue_idx` ON `seats` (`venueId`);--> statement-breakpoint
CREATE INDEX `ticket_types_event_idx` ON `ticketTypes` (`eventId`);--> statement-breakpoint
CREATE INDEX `tickets_booking_idx` ON `tickets` (`bookingId`);--> statement-breakpoint
CREATE INDEX `tickets_user_idx` ON `tickets` (`userId`);--> statement-breakpoint
CREATE INDEX `users_email_idx` ON `users` (`email`);