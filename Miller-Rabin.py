import random

def is_prime(n, confidence_percentage = 0.999999, print_results = True):
    if n < 11:
        print("pick a number larger than 11, to avoid infinite loops!")
        return
    #everytime we get inconclusive, our confidence of n being prime gets higher, so the chance for n being composite is divided by 4
    error_rate = 1/4
    chance_for_composite = 1

    #I am naming this q, because after we find k, q is already found as well!
    q = n - 1
    k = 0
    while q % 2 == 0:
        q /= 2
        k += 1
    q = int(q) #we don't need q to be a float, python kept turning it into a float

    #keep track of what values of "a" where chosen to not have repititions
    chosen_a_values = []

    while 1 - chance_for_composite < confidence_percentage:
        a = random.randint(2, n - 1)

        #if the chosen "a" value was already used, pick a new value
        if a in chosen_a_values:
            continue

        result = miller_rabin_iteration(n, a, q, k)
        if print_results:
            print(result)

        if result == "inconclusive":
            chance_for_composite *= error_rate
        else:
            return False
    return True


def miller_rabin_iteration(n, a, q, k):
    #there is a really handy function in python which calculates a^q mod n without running into overflows with huge numbers
    if pow(a, q, n) == 1:
        return "inconclusive"
    
    for j in range(k):
        if pow(a, (2 ** j) * q, n) == n - 1:
            return "inconclusive"
    return "composite"

#some prime numbers from wikipedia
print(is_prime(999999000001))
print(is_prime(6700417, print_results=False))
print(is_prime(6700411, print_results=False))

print(is_prime(37, print_results=False))
print(is_prime(35))
print(is_prime(97, print_results=False))

