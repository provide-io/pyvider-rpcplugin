grep -r 'def ' * | sed -E 's/.*def //g;s/\(.*//g' |sort -h | uniq -c | sort -d
