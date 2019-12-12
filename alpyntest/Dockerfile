FROM alpine:latest

ARG USER_ID
ARG GROUP_ID

# Dockerfile shamelessly based on:
# https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/blob/master/Dockerfile

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

ADD startup.sh /etc/profile.d/startup.sh
ADD discover-ip.sh /usr/local/bin/discover-ip.sh

RUN echo "**** configuring user ****" && \
        addgroup -g ${GROUP_ID} pentest && \
        adduser -h /home/pentest -s /bin/sh -G pentest -D -u ${USER_ID} pentest && \
    echo "**** install Python ****" && \
        apk add --no-cache python3 && \
        if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    echo "**** install pip ****" && \
        python3 -m ensurepip && \
        rm -r /usr/lib/python*/ensurepip && \
        pip3 install --no-cache --upgrade pip setuptools wheel && \
        if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    echo "**** install git ****" && \
        apk add git && \
        mkdir /tools && cd /tools && \
    echo "**** install csvkit ****" && \
        pip install csvkit && \
    echo "**** install ldapsearch-ad ****" && \
        git clone https://github.com/yaap7/ldapsearch-ad && \
        pip install -r ldapsearch-ad/requirements.txt && \
        ln -s /tools/ldapsearch-ad/ldapsearch-ad.py /usr/local/bin/ && \
    echo "**** install various scripts ****" && \
        git clone https://github.com/yaap7/miSCripts && \
        ln -s /tools/miSCripts/parse-secretsdump.sh /usr/local/bin/ && \
        ln -s /tools/miSCripts/tiny_scripts/ntlmsum /usr/local/bin/ && \
        ln -s /tools/miSCripts/tiny_scripts/grep-ip.py /usr/local/bin/ && \
        ln -s /tools/miSCripts/tiny_scripts/unhex-passwords.py /usr/local/bin/ && \
    echo "**** install other tools' dependencies ****" && \
        apk add gcc make libffi-dev libc-dev python3-dev openssl-dev && \
    echo "**** install impacket ****" && \
        git clone https://github.com/SecureAuthCorp/impacket && \
        cd impacket && \
        pip install -r requirements.txt && \
        python ./setup.py install && \
        cd .. && \
    echo "**** install pypykatz ****" && \
        git clone https://github.com/skelsec/pypykatz && \
        cd pypykatz && \
        python ./setup.py install && \
        cd .. && \
    echo "**** install lsassy ****" && \
        git clone https://github.com/Hackndo/lsassy && \
        cd lsassy && \
        pip install -r requirements.txt && \
        python ./setup.py install && \
        cd .. && \
    echo "**** install ntlmrecon ****" && \
        git clone https://github.com/sachinkamath/ntlmrecon && \
        cd ntlmrecon && \
        pip install -r requirements.pip && \
        python ./setup.py install && \
        cd .. && \
    echo "**** install Enum4LinuxPy ****" && \
        git clone https://github.com/0v3rride/Enum4LinuxPy && \
        cd Enum4LinuxPy && \
        pip install -r requirements.txt && \
        chmod a+x Enum4LinuxPy.py && \
        ln -s /tools/Enum4LinuxPy/Enum4LinuxPy.py /usr/local/bin/Enum4LinuxPy.py && \
        ln -s /tools/Enum4LinuxPy/Enum4LinuxPy.py /usr/local/bin/enum4linuxpy.py && \
        cd .. && \
    echo "**** NOT installing CrackMapExec. ****" && \
    echo "**** still have issues with python3 ****" && \
    echo "**** Finshed ****"
