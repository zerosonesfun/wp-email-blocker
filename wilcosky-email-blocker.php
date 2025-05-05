<?php
/**
 * Plugin Name: Wilcosky Email Registration Blocker
 * Description: Block specific email domains and full email addresses from registering on your WordPress site—mandatory across all entry points including REST API and custom forms.
 * Version: 1.3.11
 * Author: Billy Wilcosky
 * Text Domain: wilcosky-email-blocker
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Wilcosky_ERB {
    private $opt_domains        = 'wilcosky_erb_blocked_domains';
    private $opt_emails         = 'wilcosky_erb_blocked_emails';
    private $opt_cleanup_uninst = 'wilcosky_erb_cleanup_on_uninstall';
    private $opt_log_limit      = 'wilcosky_erb_max_log_limit';
    private $opt_enable_predefined = 'wilcosky_erb_enable_predefined_domains';
    private static $cached      = null;

    private $predefined_domains = [
        '10minutemail.com', '1secmail.com', 'mailinator.com', 'trashmail.com', 'temp-mail.org',
        'yopmail.com', 'maildrop.cc', 'throwawaymail.com', 'spamgourmet.com', 'mailnesia.com',
        'easytrashmail.com', 'mintemail.com', 'dispostable.com', 'fakemailgenerator.com',
        'fakeinbox.com', 'spam4.me', 'nomail.ch', 'mailcatch.com', 'shreddemail.com',
        'mail-temporaire.fr', 'tempail.com', 'guerrillamail.com', 'sharklasers.com',
        'guerrillamailblock.com', 'privy-mail.net', 'temp-mail.io', 'minuteinbox.com',
        'getnada.com', 'nada.email', 'spamex.com', 'mytemp.email', '33mail.com', 'mail6.io',
        'temp-mail.pro', 'moakt.com', 'anonbox.net', 'mailpoof.com', 'tempinbox.xyz',
        'yopmail.fr', 'mailwatch.cc', 'inboxbear.com', 'guerrillamail.de', 'yopmail.net',
        'mintemail.io', 'mail.tm', 'mail7.io', 'gmial.com', 'emailondeck.com', 'getairmail.com',
        'mail.ru', 'yandex.ru', 'inbox.ru', 'rambler.ru', 'bk.ru', 'list.ru', 'bigmir.net',
        'ukr.net', 'abv.bg', 'mail.kz', 'hanmail.net', 'nate.com', 'voxmail.hu', 'centrum.cz',
        'wp.pl', 'o2.pl', 'interia.pl', 'seznam.cz', 't-online.de', 'gmx.de', 'web.de',
        'freenet.de', 'arcor.de', 'post.cz', 'slovak.post.sk', 'mail.ee', 'mail.bg',
        'netcourrier.com', 'laposte.net', 'ziggo.nl', 'planet.nl', 'freemail.hu', 'wp.eu',
        'bluewin.ch', 'hispeed.ch', 'tele2.nl', 'wanadoo.es', 'terra.es', 'iol.pt', 'sapo.pt',
        'globo.com', 'uol.com.br', 'bol.com.br', 'terra.com.br', 'yahoo.co.in', 'mail2world.com',
        'mailcatch.com.au', 'bigpond.com', 'optusnet.com.au', 'virginmedia.com'
    ];

    public function __construct() {
        add_action( 'plugins_loaded',            [ $this, 'load_text_domain' ] );
        add_action( 'admin_menu',                [ $this, 'add_settings_page' ] );
        add_action( 'admin_init',                [ $this, 'register_settings' ] );
        add_action( 'admin_init',                [ $this, 'handle_clear_logs' ] );
        add_action( 'update_option_wilcosky_erb_blocked_domains', [ $this, 'wilcosky_clear_block_cache' ] );
        add_action( 'update_option_wilcosky_erb_enable_predefined_domains', [ $this, 'wilcosky_clear_block_cache' ] );
        add_action( 'update_option_wilcosky_erb_blocked_emails', [ $this, 'wilcosky_clear_block_cache' ] );
        add_filter( 'registration_errors',       [ $this, 'check_blocked_email' ], 10, 3 );
        add_filter( 'pre_user_email',            [ $this, 'pre_user_email_block' ], 10, 1 );
        add_filter( 'rest_pre_insert_user',      [ $this, 'rest_pre_insert_user_block' ], 10, 2 );
    }

    public function load_text_domain() {
        load_plugin_textdomain(
            'wilcosky-email-blocker',
            false,
            dirname( plugin_basename( __FILE__ ) ) . '/languages/'
        );
    }

    public function register_settings() {
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_domains,
            [
                'type'              => 'array',
                'sanitize_callback' => [ $this, 'sanitize_domains' ],
                'default'           => [],
            ]
        );
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_emails,
            [
                'type'              => 'array',
                'sanitize_callback' => [ $this, 'sanitize_emails' ],
                'default'           => [],
            ]
        );
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_log_limit,
            [
                'type'              => 'boolean',
                'sanitize_callback' => 'rest_sanitize_boolean',
                'default'           => false,
            ]
        );
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_enable_predefined,
            [
                'type'              => 'boolean',
                'sanitize_callback' => 'rest_sanitize_boolean',
                'default'           => false,
            ]
        );
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_cleanup_uninst,
            [
                'type'              => 'boolean',
                'sanitize_callback' => 'rest_sanitize_boolean',
                'default'           => false,
            ]
        );

    }

    public function sanitize_domains( $input ) {
        if ( is_string( $input ) ) {
            $input = preg_split( '/\r?\n/', $input );
        }
        $clean = [];
        foreach ( (array) $input as $line ) {
            $d = trim( strtolower( $line ) );
            if ( $d === '' ) {
                continue;
            }
            $clean[] = sanitize_text_field( $d );
        }
        return array_values( array_unique( $clean ) );
    }

    public function sanitize_emails( $input ) {
        if ( is_string( $input ) ) {
            $input = preg_split( '/\r?\n/', $input );
        }
        $clean = [];
        foreach ( (array) $input as $line ) {
            $e = trim( strtolower( $line ) );
            if ( $e === '' || ! is_email( $e ) ) {
                continue;
            }
            $clean[] = sanitize_email( $e );
        }
        return array_values( array_unique( $clean ) );
    }

    private function get_block_lists() {
    $cache_key = 'wilcosky_erb_block_lists';
    $cached = get_transient($cache_key);

    if ($cached !== false) {
        return $cached;
    }

    $domains = (array) get_option($this->opt_domains, []);
    $emails = (array) get_option($this->opt_emails, []);
    $predefined_enabled = get_option( $this->opt_enable_predefined, false );

    if ($predefined_enabled) {
        $domains = array_merge($domains, $this->predefined_domains);
    }

    $result = [
        'domains' => array_map('strtolower', $domains),
        'emails'  => array_map('strtolower', $emails),
    ];

    set_transient($cache_key, $result, DAY_IN_SECONDS); // Cache for 1 day
    return $result;
}
    public function wilcosky_clear_block_cache() {
    delete_transient('wilcosky_erb_block_lists');
}

    private function is_blocked( $email, $log = true ) {
    $lists    = $this->get_block_lists();
    $email_lc = strtolower( $email );

    if ( in_array( $email_lc, $lists['emails'], true ) ) {
        if ( $log ) {
            $this->log_blocked_email( $email_lc );
        }
        return true;
    }

    $parts = explode( '@', $email_lc );
    if ( count( $parts ) === 2 && in_array( $parts[1], $lists['domains'], true ) ) {
        if ( $log ) {
            $this->log_blocked_email( $email_lc );
        }
        return true;
    }

    return false;
}

    private function log_blocked_email( $email ) {
    $log = (array) get_option( 'wilcosky_erb_block_log', [] );
    $log[] = [
        'email' => $email,
        'time'  => current_time( 'mysql' ),
    ];

    $max_log_limit_enabled = get_option( $this->opt_log_limit, false );
    if ( $max_log_limit_enabled && count( $log ) > 100 ) {
        $log = array_slice( $log, -100 ); // keep last 100 entries
    }

    update_option( 'wilcosky_erb_block_log', $log );
}

    public function check_blocked_email( $errors, $sanitized_user_login, $user_email ) {
        if ( $this->is_blocked( $user_email ) ) {
            $errors->add(
                'erb_blocked_email',
                __( 'Registration forbidden: email domain or address is blocked.', 'wilcosky-email-blocker' )
            );
        }
        return $errors;
    }

    public function pre_user_email_block( $email ) {
        if ( $this->is_blocked( $email ) ) {
            wp_die(
                esc_html__( 'Registration forbidden: email domain or address is blocked.', 'wilcosky-email-blocker' ),
                esc_html__( 'Forbidden', 'wilcosky-email-blocker' ),
                [ 'response' => 403 ]
            );
        }
        return $email;
    }

    public function rest_pre_insert_user_block( $prepared_user, $request ) {
        if ( ! empty( $prepared_user->user_email ) && $this->is_blocked( $prepared_user->user_email ) ) {
            list( , $blocked_domain ) = explode( '@', $prepared_user->user_email );
            return new WP_Error(
                'erb_blocked_email_rest',
                sprintf(
                    __( 'Registration forbidden via REST API: email domain "%s" or address "%s" is blocked.', 'wilcosky-email-blocker' ),
                    $blocked_domain,
                    $prepared_user->user_email
                ),
                [ 'status' => 403 ]
            );
        }
        return $prepared_user;
    }

    public function add_settings_page() {
        add_options_page(
            __( 'Email Registration Blocker', 'wilcosky-email-blocker' ),
            __( 'Email Blocker', 'wilcosky-email-blocker' ),
            'manage_options',
            'wilcosky-erb',
            [ $this, 'settings_page_html' ]
        );
    }

    public function handle_clear_logs() {
    if ( isset( $_POST['action'] ) && $_POST['action'] === 'clear_logs' ) {
        check_admin_referer( 'wilcosky_erb_clear_logs' );

        // Clear the logs
        update_option( 'wilcosky_erb_block_log', [] );

        // Add an admin notice for feedback
        add_action( 'admin_notices', function() {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Logs cleared successfully.', 'wilcosky-email-blocker' ) . '</p></div>';
        } );
    }
}

    public function settings_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Forbidden', 'wilcosky-email-blocker' ) );
        }

        // Handle test-email submission
        $test_result = null;
        if ( isset( $_POST['wilcosky_erb_test_email'] ) ) {
    check_admin_referer( 'wilcosky_erb_settings' );
    $test_email = sanitize_email( wp_unslash( $_POST['wilcosky_erb_test_email'] ) );
    if ( empty( $test_email ) || ! is_email( $test_email ) ) {
        $test_result = __( 'Invalid email address.', 'wilcosky-email-blocker' );
    } elseif ( $this->is_blocked( $test_email, false ) ) { // Pass `false` to skip logging
        $test_result = __( 'This email WOULD be blocked.', 'wilcosky-email-blocker' );
    } else {
        $test_result = __( 'This email would be allowed.', 'wilcosky-email-blocker' );
    }
}

        $blocked_domains       = get_option( $this->opt_domains, [] );
        $blocked_emails        = get_option( $this->opt_emails, [] );
        $max_log_limit_enabled = get_option( $this->opt_log_limit, false );
        $predefined_enabled    = get_option( $this->opt_enable_predefined, false );
        $cleanup_on_uninstall = get_option( $this->opt_cleanup_uninst, false );

        // Build log-summary
        $logs = (array) get_option( 'wilcosky_erb_block_log', [] );
        $email_addresses = array_column( $logs, 'email' );
        $email_counts = array_count_values( $email_addresses );
        if ( $max_log_limit_enabled && count( $email_counts ) > 100 ) {
            $email_counts = array_slice( $email_counts, 0, 100, true );
        }
        $multi_blocked  = array_filter( $email_counts, fn( $c ) => $c > 1 );
        arsort( $multi_blocked );
        $single_blocked = array_diff_key( $email_counts, $multi_blocked );

        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'Email Registration Blocker Settings', 'wilcosky-email-blocker' ); ?></h1>
            <?php if ( $test_result ) : ?>
                <div class="notice notice-info"><p><?php echo esc_html( $test_result ); ?></p></div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php settings_fields( 'wilcosky_erb_settings' ); ?>
                <table class="form-table">
                    <tr>
                        <th><?php esc_html_e( 'Blocked Domains', 'wilcosky-email-blocker' ); ?></th>
                        <td>
                            <textarea name="<?php echo esc_attr( $this->opt_domains ); ?>" rows="5" class="large-text code"><?php
                                echo esc_textarea( implode( "\n", $blocked_domains ) );
                            ?></textarea>
                            <p class="description"><?php esc_html_e( 'One domain per line (e.g., example.com)', 'wilcosky-email-blocker' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e( 'Blocked Emails', 'wilcosky-email-blocker' ); ?></th>
                        <td>
                            <textarea name="<?php echo esc_attr( $this->opt_emails ); ?>" rows="5" class="large-text code"><?php
                                echo esc_textarea( implode( "\n", $blocked_emails ) );
                            ?></textarea>
                            <p class="description"><?php esc_html_e( 'One email per line (e.g., user@example.com)', 'wilcosky-email-blocker' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php printf(wp_kses(sprintf(__('Enable Predefined <a href="%s" target="_blank">Domain List</a>', 'wilcosky-email-blocker'), esc_url('https://github.com/zerosonesfun/wp-email-blocker/wiki/Known-Spam-Email-Domains')), ['a' => ['href' => [], 'target' => []]])); ?>
</th>
                        <td>
                            <label>
                                <input type="hidden" name="<?php echo esc_attr( $this->opt_enable_predefined ); ?>" value="0" />
                                <input type="checkbox" name="<?php echo esc_attr( $this->opt_enable_predefined ); ?>" value="1" <?php checked( true, $predefined_enabled ); ?> />
                                <?php esc_html_e( 'Enable', 'wilcosky-email-blocker' ); ?>
                           </label>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e( 'Clean up on Uninstall', 'wilcosky-email-blocker' ); ?></th>
                        <td>
                            <label>
                                <input type="hidden" name="<?php echo esc_attr( $this->opt_cleanup_uninst ); ?>" value="0" />
                                <input type="checkbox" name="<?php echo esc_attr( $this->opt_cleanup_uninst ); ?>" value="1" <?php checked( true, $cleanup_on_uninstall ); ?> />
                                <?php esc_html_e( 'Yes', 'wilcosky-email-blocker' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e( 'Limit Log to 100 Emails', 'wilcosky-email-blocker' ); ?></th>
                        <td>
                            <label>
                                <input type="hidden" name="<?php echo esc_attr( $this->opt_log_limit ); ?>" value="0" />
                                <input type="checkbox" name="<?php echo esc_attr( $this->opt_log_limit ); ?>" value="1" <?php checked( true, $max_log_limit_enabled ); ?> />
                                <?php esc_html_e( 'Enable', 'wilcosky-email-blocker' ); ?>
                            </label>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form><br>

            <hr />

            <h2><?php esc_html_e( 'Test an Email', 'wilcosky-email-blocker' ); ?></h2>
            <form method="post">
                <?php wp_nonce_field( 'wilcosky_erb_settings' ); ?>
                <input type="email" name="wilcosky_erb_test_email" placeholder="<?php esc_attr_e( 'Enter an email to test...', 'wilcosky-email-blocker' ); ?>" class="regular-text" />
                <?php submit_button( __( 'Test Email', 'wilcosky-email-blocker' ), 'primary', 'test_email', false ); ?>
            </form><br>

            <hr />

            <h2><?php esc_html_e( 'Log', 'wilcosky-email-blocker' ); ?></h2>
            <p>The number of times the same email has been blocked is in parentheses.</p>
            <ul>
                <?php foreach ( $multi_blocked as $email => $count ) : ?>
                    <li><?php echo esc_html( $email ); ?> (<?php echo esc_html( $count ); ?>)</li>
                <?php endforeach; ?>
                <?php foreach ( $single_blocked as $email => $count ) : ?>
                    <li><?php echo esc_html( $email ); ?> (1)</li>
                <?php endforeach; ?>
            </ul>
        </div>

          <hr />

          <h2><?php esc_html_e( 'Manage Log', 'wilcosky-email-blocker' ); ?></h2>
          <p style="color:red">Careful! With one click, your log is gone.</p>
          <form method="post">
                             <?php wp_nonce_field( 'wilcosky_erb_clear_logs' ); ?>
                             <input type="hidden" name="action" value="clear_logs" />
                             <?php submit_button( __( 'Clear Logs', 'wilcosky-email-blocker' ), 'delete', 'clear_logs', false ); ?>
          </form>
        <?php
    }
}

new Wilcosky_ERB();

/**
 * Clean up options on plugin deactivation.
 */
function wilcosky_erb_deactivate() {
    delete_option('wilcosky_erb_enable_predefined_domains');
    delete_option('wilcosky_erb_cleanup_on_uninstall');
    delete_option('wilcosky_erb_max_log_limit');
}
register_deactivation_hook(__FILE__, 'wilcosky_erb_deactivate');

/**
 * Clean up options (including block log) on uninstall if enabled.
 */
function wilcosky_erb_uninstall() {
    if ( get_option( 'wilcosky_erb_cleanup_on_uninstall', false ) ) {
        delete_option( 'wilcosky_erb_blocked_domains' );
        delete_option( 'wilcosky_erb_blocked_emails' );
        delete_option( 'wilcosky_erb_max_log_limit' );
        delete_option( 'wilcosky_erb_cleanup_on_uninstall' );
        delete_option( 'wilcosky_erb_block_log' );
        delete_option( 'wilcosky_erb_enable_predefined_domains' ); 
    }
}
register_uninstall_hook( __FILE__, 'wilcosky_erb_uninstall' );
