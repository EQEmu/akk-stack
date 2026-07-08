######################################################
# 7.1 Apache
######################################################

FROM php:7.1-apache

# Debian Buster was archived after LTS ended; its package repos no
# longer exist on deb.debian.org or security.debian.org. Point apt at
# archive.debian.org so the image remains buildable. buster-updates
# does not exist on the archive and is removed. Check-Valid-Until is
# disabled because archived Release files are no longer refreshed.
RUN sed -i \
	-e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' \
	-e 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' \
	/etc/apt/sources.list && \
	sed -i '/buster-updates/d' /etc/apt/sources.list && \
	echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive

RUN apt-get update && apt-get install -y \
	libbz2-dev \
	libc-client-dev \
	libcurl4-gnutls-dev \
	libkrb5-dev \
	libmcrypt-dev \
	libpng-dev \
	libreadline-dev \
	libssl-dev \
	libxml2-dev \
	libxslt-dev \
	git

######################################################
# Enable / Compile PHP modules
######################################################
RUN docker-php-ext-install -j$(nproc) bcmath
RUN docker-php-ext-install -j$(nproc) calendar
RUN docker-php-ext-install -j$(nproc) curl
RUN docker-php-ext-install -j$(nproc) dba
RUN docker-php-ext-install -j$(nproc) exif
RUN docker-php-ext-install -j$(nproc) gd
RUN docker-php-ext-install -j$(nproc) gettext
RUN docker-php-ext-install -j$(nproc) mcrypt
RUN docker-php-ext-install -j$(nproc) mysqli
RUN docker-php-ext-install -j$(nproc) opcache
RUN docker-php-ext-install -j$(nproc) pdo_mysql
RUN docker-php-ext-install -j$(nproc) soap
RUN docker-php-ext-install -j$(nproc) sockets
RUN docker-php-ext-install -j$(nproc) xsl
RUN docker-php-ext-install -j$(nproc) zip

RUN echo "opcache.enable=1" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.memory_consumption=512" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.interned_strings_buffer=64" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.max_accelerated_files=32531" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.save_comments=1" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.fast_shutdown=0" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.revalidate_freq=600000" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini && \
    echo "opcache.validate_timestamps=0" >> /usr/local/etc/php/conf.d/docker-php-ext-opcache.ini

######################################################
# Apache modules
######################################################
RUN a2enmod deflate
RUN a2enmod expires
RUN a2enmod file_cache
RUN a2enmod headers
RUN a2enmod rewrite
