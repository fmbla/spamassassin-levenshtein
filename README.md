# spamassassin-levenshtein
Measure Levenshtein distance for targets in spamassassin

# Functions

## check_levenshtein
Compare From:addr against all To:addr using plugin config settings

## check_levenshtein_from( str <domain>, int [distance], bool [use_tld] default: 0 )
Compare From addresses against `str domain` return true if distance equal or less than `int distance`

## check_levenshtein_name( str <word>, int [distance], bool [allow_exact_match] default: 1 )
Compare From name against `str word` return true if distance equal or less than `int distance` 

## check_levenshtein_reply( int [distance] default: auto, bool [use_tld] default: 0 )
Compare From:addr to Reply-To:addr return true if distance qual or less than `int distance` 

# Config Settings

## levenshtein_short_length
Default: 10
Used for determining which distance to use automatically
## levenshtein_short_dist
Default: 1
If string is less than short length this value is used
## levenshtein_long_dist
Default: 2
If string is greater than than short length this value is used
## levenshtein_use_tld
Default: 0
Use take TLD into consideration when comparing distance
