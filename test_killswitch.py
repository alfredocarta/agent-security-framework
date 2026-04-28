from interceptor import security_interceptor

print("--- KILL SWITCH TEST ---")

ok1, msg1 = security_interceptor("db_agent", "write_db", "DROP ALL TABLES")
print(f"Attempt 1: {msg1}")

ok2, msg2 = security_interceptor("db_agent", "read_db", "SELECT * FROM users")
print(f"Attempt 2 (post-suspension): {msg2}")
