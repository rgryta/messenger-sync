-- What Messenger adds to the encrypted device whose keys whatsapp-client keeps in the `device`
-- schema: whose device it is, and Meta's UUID for it. A Messenger device has no WhatsApp
-- pairing record, so `device.account`'s pairing columns stay empty.
CREATE TABLE client.device (
    id          smallint PRIMARY KEY CHECK (id = 1),
    fbid        text NOT NULL,
    device_id   integer NOT NULL,
    device_uuid text NOT NULL
);
