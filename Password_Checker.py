import hashlib
import re

def check_password_strength(password):
    """
    Evaluates password strength based on length, case, numbers, and special characters.
    """
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Make it at least 8-12 characters long.")

    # Character type checks
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters (e.g., !, @, #).")

    # Rating determination
    if score >= 5:
        rating = "STRONG"
    elif score >= 3:
        rating = "MEDIUM"
    else:
        rating = "WEAK"

    return rating, feedback


def hash_text(text, algorithm="sha256"):
    """
    Hashes text using the specified algorithm.
    Supported algorithms: sha256, sha512
    """
    bytes_data = text.encode('utf-8')
    
    if algorithm == "sha256":
        return hashlib.sha256(bytes_data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(bytes_data).hexdigest()
    else:
        raise ValueError("Unsupported algorithm")


def main():
    print("=== ISA Security Toolkit: Strength Checker & Multi-Hash Tool ===")
    print("1. Check password strength & hash password")
    print("2. Verify a password against a stored hash")
    
    choice = input("\nSelect an option (1 or 2): ").strip()
    
    if choice == "1":
        pwd = input("Enter password to analyze and hash: ")
        
        # Check Strength
        rating, feedback = check_password_strength(pwd)
        print("\n--- Password Strength Analysis ---")
        print(f"Strength Rating: {rating}")
        if feedback:
            print("Suggestions for improvement:")
            for item in feedback:
                print(f"  - {item}")
        else:
            print("Great job! Your password meets all basic security standards.")

        # Generate Hashes
        print("\n--- Generated Hashes ---")
        print(f"SHA-256 (256-bit): {hash_text(pwd, 'sha256')}")
        print(f"SHA-512 (512-bit): {hash_text(pwd, 'sha512')}")
        print("-" * 50)
        
    elif choice == "2":
        print("\nSelect Algorithm for Verification:")
        print("a. SHA-256")
        print("b. SHA-512")
        alg_choice = input("Choice (a/b): ").strip().lower()
        
        alg_map = {"a": "sha256", "b": "sha512"}
        selected_alg = alg_map.get(alg_choice, "sha256")
        
        stored_hash = input(f"Enter the target {selected_alg.upper()} hash: ").strip()
        attempt = input("Enter the password to test: ").strip()
        
        attempt_hash = hash_text(attempt, selected_alg)
        
        print("\n--- Verification Result ---")
        if attempt_hash == stored_hash:
            print("[SUCCESS] Password MATCHES! Access Granted.")
        else:
            print("[FAILED] Password DOES NOT match! Integrity Check Failed.")
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
