from app1.dynamo_utils import save_progress, load_progress

if __name__ == "__main__":
    user_id = "n11605618"  # your qut-username without @qut.edu.au if that’s what’s in your table

    # 1️⃣ Save progress
    save_progress(user_id, 75)
    print(f"Saved progress 75 for {user_id}")

    # 2️⃣ Load progress
    progress = load_progress(user_id)
    print(f"Loaded progress for {user_id}: {progress}")

    # 3️⃣ Update progress
    save_progress(user_id, 90)
    print(f"Updated progress 90 for {user_id}")

    # 4️⃣ Load again
    progress = load_progress(user_id)
    print(f"Loaded updated progress for {user_id}: {progress}")
