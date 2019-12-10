getent passwd | grep -q '^pentest' && [ "$(id -u)" -eq 0 ] && su - pentest
alias l='ls --color -lh'
alias ll='ls --color -alh'
export PS1='\[\033[01;31m\]\u\[\033[00m\]@\[\033[01;36m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
cd /data
