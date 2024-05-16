#FROM lscr.io/linuxserver/openssh-server:latest
FROM debian:stable-slim

RUN apt update && apt upgrade -y

RUN apt install -y openssh-server

RUN useradd el
RUN passwd -d el
RUN chpasswd el:password1

RUN echo >>/etc/ssh/sshd_config "AllowAgentForwarding yes"
RUN echo >>/etc/ssh/sshd_config "AllowTcpForwarding yes"
RUN echo >>/etc/ssh/sshd_config "Port 2221"

CMD service ssh restart

EXPOSE 2221


