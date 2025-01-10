FROM mysql:8 as builder
ENV MYSQL_ROOT_PASSWORD=p_ssW0rd
ENV MYSQL_DATABASE=sakila
ENV MYSQL_USER=sakila
ENV MYSQL_PASSWORD=p_ssW0rd

COPY ./1-sakila-schema.sql /docker-entrypoint-initdb.d/step_1.sql
COPY ./2-sakila-data.sql /docker-entrypoint-initdb.d/step_2.sql
COPY ./3-sakila-complete.sql /docker-entrypoint-initdb.d/step_3.sql

# https://serverfault.com/questions/930141/creating-a-mysql-image-with-the-db-preloaded
# https://serverfault.com/questions/796762/creating-a-docker-mysql-container-with-a-prepared-database-scheme
RUN ["sed", "-i", "s/exec \"$@\"/echo \"skipping...\"/", "/usr/local/bin/docker-entrypoint.sh"]

USER mysql
RUN ["/usr/local/bin/docker-entrypoint.sh", "mysqld"]

FROM mysql:8
ENV MYSQL_ROOT_PASSWORD=p_ssW0rd
ENV MYSQL_DATABASE=sakila
ENV MYSQL_USER=sakila
ENV MYSQL_PASSWORD=p_ssW0rd

COPY --from=builder /var/lib/mysql /data
RUN rm -rf /var/lib/mysql/*
RUN mv /data/* /var/lib/mysql/

USER mysql

# See: https://dev.to/mdemblani/docker-container-uncaught-kill-signal-10l6
COPY ./signal-listener.sh /sakila/run.sh
# Entrypoint overload to catch the ctrl+c and stop signals
ENTRYPOINT ["/bin/bash", "/sakila/run.sh"]
