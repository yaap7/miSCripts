getent passwd | grep -q '^pentest' && [ "$(id -u)" -eq 0 ] && su - pentest
alias l='ls --color -lh'
alias ll='ls --color -alh'
if [ "$(id -u)" -eq 0 ] ; then
    export PS1='\[\033[01;31m\]\u\[\033[00m\]@\[\033[01;36m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    export PS1='\[\033[01;32m\]\u\[\033[00m\]@\[\033[01;36m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
fi
cd /data
