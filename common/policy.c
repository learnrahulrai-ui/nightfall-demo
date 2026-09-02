

int policy_action(int level)
{
    if (level == 0) return 0;
    if (level >= 2) return 2;
    return 1;
}