<?php
// Disposable Docker fixture only. Never run against an existing website.
if (getenv('WORDPRESS_DB_PASSWORD') !== 'fixture-only' || getenv('WORDPRESS_DB_HOST') !== 'db') {
    throw new RuntimeException('Refusing to install outside the disposable fixture');
}
define('WP_INSTALLING', true);
$_SERVER['HTTP_HOST'] = 'wordpress';
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
add_filter('pre_wp_mail', '__return_true');
if (!is_blog_installed()) {
    wp_install('PHP2Shell fixture', 'fixture_admin', 'fixture@example.invalid', false, '', 'fixture-only-password');
}
update_option('home', 'http://wordpress');
update_option('siteurl', 'http://wordpress');
echo "Disposable WordPress fixture installed.\n";
