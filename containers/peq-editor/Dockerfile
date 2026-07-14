FROM php:8.5-apache

# The editor code uses mysqli, json, and session. json and session are
# built in; mysqli needs installing. opcache is NOT installed here
# because as of PHP 8.5 it is statically compiled into PHP itself and
# can no longer be built as a shared extension (attempting to install
# it fails the build); the tuning below still applies to the built-in.
RUN docker-php-ext-install -j$(nproc) mysqli

# 329 files in peqphpeditor use short open tags. The compiled default
# is On but official images ship no php.ini, so pin it explicitly
# rather than rely on that accident.
RUN echo "short_open_tag=On" > /usr/local/etc/php/conf.d/short-open-tag.ini

RUN { \
    echo "opcache.enable=1"; \
    echo "opcache.memory_consumption=512"; \
    echo "opcache.interned_strings_buffer=64"; \
    echo "opcache.max_accelerated_files=32531"; \
    echo "opcache.save_comments=1"; \
    echo "opcache.revalidate_freq=600000"; \
    echo "opcache.validate_timestamps=0"; \
  } > /usr/local/etc/php/conf.d/opcache-tuning.ini

RUN a2enmod deflate expires file_cache headers rewrite
