-- Devices found on the network are recognised by hardware address when their IP
-- changes; password reuse at sudo prompts can be set per connection
-- (NULL = follow the app setting).
ALTER TABLE profiles ADD COLUMN mac TEXT;
ALTER TABLE profiles ADD COLUMN reuse_password INTEGER;
