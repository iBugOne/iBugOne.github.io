#!/usr/bin/python3
import sys
import os
import regex
# noinspection PyPackageRequirements
import tld
# noinspection PyPackageRequirements
from tld.utils import TldDomainNotFound

# These types of files frequently get caught as "misleading link"
SAFE_EXTENSIONS = set(('txt', 'js', 'htm', 'html', 'css', 'php', 'py', 'java', 'rb'))

# This is the same value as in production
LEVEN_DOMAIN_DISTANCE = 3

# Leave this blank as it doesn't matter
SE_SITES_DOMAINS = []

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def contains_tld(s):
    # Don't interfere with this
    return True


def malicious_link(s, site, *args):
    link_regex = r"<a href=\"([^\"]+)\"[^>]*>([^<]+)<\/a>"
    compiled = regex.compile(link_regex)
    search = compiled.search(s)
    if search is None:
        return False, ''

    # TODO: This print is test code. It should not appear in production code.
    # It's intended to make output results clearer.
    print(search[0])
    # End of test code

    href, text = search[1], search[2]
    try:
        parsed_href = tld.get_tld(href, as_object=True)
        if parsed_href.tld in SE_SITES_DOMAINS:
            return False, ''
        if contains_tld(text) and ' ' not in text:
            parsed_text = tld.get_tld(text, fix_protocol=True, as_object=True)
        else:
            raise tld.exceptions.TldBadUrl('Link text is not a URL')
    except tld.exceptions.TldDomainNotFound:
        print('TldDomainNotFound')
        return False, ''
    except tld.exceptions.TldBadUrl:
        print('TldBadUrl')
        return False, ''
    except ValueError as err:
        print('ValueError')
        return False, ''

    print(parsed_text.domain, parsed_text.tld)
    if parsed_text.tld.split('.')[-1] in SAFE_EXTENSIONS:
        print('Safe extension')
        return False, ''
    elif levenshtein(parsed_href.domain.lower(), parsed_text.domain.lower()) > LEVEN_DOMAIN_DISTANCE:
        return True, 'Domain {} indicated by possible misleading text {}.'.format(
            parsed_href, parsed_text
        )
    else:
        return False, ''


if __name__ == '__main__':
    for t in filter(lambda x: x.startswith('test') and x.endswith('.txt'), os.listdir('.')):
        print('Test file *{}*:'.format(t))
        with open(t, 'r') as f:
            print(malicious_link(f.read(), None, None))
            f.close()
        print('')
