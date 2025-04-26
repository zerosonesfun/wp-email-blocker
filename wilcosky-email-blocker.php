<?php
/**
 * Plugin Name: Wilcosky Email Registration Blocker
 * Description: Block specific email domains and full email addresses from registering on your WordPress site—mandatory across all entry points including REST API and custom forms.
 * Version: 1.2.1
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

    public function __construct() {
        add_action( 'admin_menu',    array( $this, 'add_settings_page' ) );
        add_action( 'admin_init',    array( $this, 'register_settings' ) );

        add_filter( 'registration_errors',  array( $this, 'check_blocked_email' ), 10, 3 );
        add_filter( 'pre_user_email',       array( $this, 'pre_user_email_block' ), 10, 1 );
        add_filter( 'rest_pre_insert_user', array( $this, 'rest_pre_insert_user_block' ), 10, 2 );
    }

    public function add_settings_page() {
        add_options_page(
            __( 'Email Registration Blocker', 'wilcosky-email-blocker' ),
            __( 'Email Blocker', 'wilcosky-email-blocker' ),
            'manage_options',
            'wilcosky-erc',
            array( $this, 'settings_page_html' )
        );
    }

    public function register_settings() {
        register_setting(
            'wilcosky_erb_settings',
            $this->opt_domains,
            array(
                'type'              => 'string',
                'sanitize_callback' => array( $this, 'sanitize_domains' ),
                'default'           => ''
            )
        );

        register_setting(
            'wilcosky_erb_settings',
            $this->opt_emails,
            array(
                'type'              => 'string',
                'sanitize_callback' => array( $this, 'sanitize_emails' ),
                'default'           => ''
            )
        );

        register_setting(
            'wilcosky_erb_settings',
            $this->opt_cleanup_uninst,
            array(
                'type'              => 'boolean',
                'sanitize_callback' => array( $this, 'sanitize_cleanup_flag' ),
                'default'           => 0
            )
        );
    }

    public function sanitize_domains( $input ) {
        $lines = preg_split( '/?
/', $input );
        $clean = array();
        foreach ( $lines as $line ) {
            $d = trim( $line );
            if ( $d === '' ) {
                continue;
            }
            $clean[] = sanitize_text_field( strtolower( $d ) );
        }
        return implode( PHP_EOL, $clean );
    }

    public function sanitize_emails( $input ) {
        $lines = preg_split( '/?
/', $input );
        $clean = array();
        foreach ( $lines as $line ) {
            $e = trim( $line );
            if ( $e === '' || ! is_email( $e ) ) {
                continue;
            }
            $clean[] = sanitize_email( strtolower( $e ) );
        }
        return implode( PHP_EOL, $clean );
    }

    public function sanitize_cleanup_flag( $input ) {
        return $input ? 1 : 0;
    }

    private function is_blocked( $email ) {
        $domains_opt = get_option( $this->opt_domains, '' );
        $emails_opt  = get_option( $this->opt_emails, '' );
        $domains     = array_filter( array_map( 'trim', explode( "
", strtolower( $domains_opt ) ) ) );
        $emails      = array_filter( array_map( 'trim', explode( "
", strtolower( $emails_opt ) ) ) );

        $email_lc = strtolower( $email );
        if ( in_array( $email_lc, $emails, true ) ) {
            return true;
        }
        $parts = explode( '@', $email_lc );
        if ( count( $parts ) === 2 && in_array( $parts[1], $domains, true ) ) {
            return true;
        }
        return false;
    }

    public function check_blocked_email( $errors, $sanitized_user_login, $user_email ) {
        if ( $this->is_blocked( $user_email ) ) {
            wp_die(
                esc_html__( 'Registration forbidden: email domain or address is blocked.', 'wilcosky-email-blocker' ),
                esc_html__( 'Forbidden', 'wilcosky-email-blocker' ), array( 'response' => 403 )
            );
        }
        return $errors;
    }

    public function pre_user_email_block( $email ) {
        if ( $this->is_blocked( $email ) ) {
            wp_die(
                esc_html__( 'Registration forbidden: email domain or address is blocked.', 'wilcosky-email-blocker' ),
                esc_html__( 'Forbidden', 'wilcosky-email-blocker' ), array( 'response' => 403 )
            );
        }
        return $email;
    }

    public function rest_pre_insert_user_block( $prepared_user, $request ) {
        if ( isset( $prepared_user->user_email ) && $this->is_blocked( $prepared_user->user_email ) ) {
            wp_die(
                esc_html__( 'Registration forbidden via REST API: email domain or address is blocked.', 'wilcosky-email-blocker' ),
                esc_html__( 'Forbidden', 'wilcosky-email-blocker' ), array( 'response' => 403 )
            );
        }
        return $prepared_user;
    }

    public function settings_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Forbidden', 'wilcosky-email-blocker' ) );
        }

        $test_result = null;
        if ( isset( $_POST['wilcosky_erb_test_email'] ) ) {
            check_admin_referer( 'wilcosky_erb_settings' );
            $test_email = sanitize_email( wp_unslash( $_POST['wilcosky_erb_test_email'] ) );
            if ( empty( $test_email ) || ! is_email( $test_email ) ) {
                $test_result = __( 'Invalid email address.', 'wilcosky-email-blocker' );
            } elseif ( $this->is_blocked( $test_email ) ) {
                $test_result = __( 'This email WOULD be blocked.', 'wilcosky-email-blocker' );
            } else {
                $test_result = __( 'This email would be allowed.', 'wilcosky-email-blocker' );
            }
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'Email Registration Blocker Settings', 'wilcosky-email-blocker' ); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields( 'wilcosky_erb_settings' ); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e( 'Blocked Domains', 'wilcosky-email-blocker' ); ?></th>
                        <td><textarea name="<?php echo esc_attr( $this->opt_domains ); ?>" rows="5" cols="50" class="large-text code"><?php echo esc_textarea( get_option( $this->opt_domains, '' ) ); ?></textarea><p class="description"><?php esc_html_e( 'One domain per line (e.g., example.com)', 'wilcosky-email-blocker' ); ?></p></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e( 'Blocked Emails', 'wilcosky-email-blocker' ); ?></th>
                        <td><textarea name="<?php echo esc_attr( $this->opt_emails ); ?>" rows="5" cols="50" class="large-text code"><?php echo esc_textarea( get_option( $this->opt_emails, '' ) ); ?></textarea><p class="description"><?php esc_html_e( 'One email per line (e.g., user@example.com)', 'wilcosky-email-blocker' ); ?></p></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e( 'Clean up on Uninstall', 'wilcosky-email-blocker' ); ?></th>
                        <td><label for="<?php echo esc_attr( $this->opt_cleanup_uninst ); ?>"><input type="checkbox" name="<?php echo esc_attr( $this->opt_cleanup_uninst ); ?>" id="<?php echo esc_attr( $this->opt_cleanup_uninst ); ?>" value="1" <?php checked( get_option( $this->opt_cleanup_uninst ), 1 ); ?> /> <?php esc_html_e( 'Delete all plugin data upon uninstall', 'wilcosky-email-blocker' ); ?></label></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

new Wilcosky_ERB();

/**
 * Uninstall handler: cleans up options if cleanup flag is set
 */
function wilcosky_erb_uninstall() {
    if ( get_option( 'wilcosky_erb_cleanup_on_uninstall', 0 ) ) {
        delete_option( 'wilcosky_erb_blocked_domains' );
        delete_option( 'wilcosky_erb_blocked_emails' );
        delete_option( 'wilcosky_erb_cleanup_on_uninstall' );
    }
}
register_uninstall_hook( __FILE__, 'wilcosky_erb_uninstall' );
