FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server nano \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash student \
 && echo 'student:Lab-SSC-2026' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
