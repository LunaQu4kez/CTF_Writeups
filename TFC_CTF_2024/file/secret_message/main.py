import random
import secrets

def hide(string, seed, shuffle):
    random.seed(seed)
    byts = []
    for _ in range(len(string)):
        byts.append(random.randint(0, 255))

    random.seed(shuffle)
    for i in range(100):
        random.shuffle(byts)

    return bytes([a^b for a, b in zip(string, byts)])

actual_random_number = secrets.randbelow(1_000_000_000_000_000_000)

flag = open("flag", "rb").read()

print("Give me 6 different seeds:")

seed_1 = int(input("Seed 1: "))
seed_2 = int(input("Seed 2: "))
seed_3 = int(input("Seed 3: "))
seed_4 = int(input("Seed 4: "))
seed_5 = int(input("Seed 5: "))
seed_6 = int(input("Seed 6: "))

seeds_set = set([seed_1, seed_2, seed_3, seed_4, seed_5, seed_6])

if len(seeds_set) < 6:
    print("The seeds must be different!")
    exit()

hidden_flag_1 = hide(flag, seed_1, actual_random_number)
hidden_flag_2 = hide(hidden_flag_1, seed_2, actual_random_number)
hidden_flag_3 = hide(hidden_flag_2, seed_3, actual_random_number)
hidden_flag_4 = hide(hidden_flag_3, seed_4, actual_random_number)
hidden_flag_5 = hide(hidden_flag_4, seed_5, actual_random_number)
hidden_flag_6 = hide(hidden_flag_5, seed_6, actual_random_number)

print(f"Here is your result:", hidden_flag_6)
