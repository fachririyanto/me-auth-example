<?php
/**
 * Plugin Name:     Me Auth Example
 * Author:          Fachri Riyanto
 * Author URI:      https://fachririyanto.com
 * Version:         1.0.0
 */
if ( ! ABSPATH ) {
    return;
}
define( 'ME_AUTH_EXAMPLE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Plugin Controller.
 * 
 * @since 1.0.0
 */
class Me_Auth_Example {
    /**
     * API namespace.
     * 
     * @var string
     */
    private $api_namespace = 'me-auth-example';

    /**
     * Token secret key.
     */
    private $token_secret = 'me_auth_example_secret';

    /**
     * Setup controller.
     * 
     * @uses register_activation_hook()
     * @uses register_deactivation_hook()
     * @uses add_action()
     * 
     * @since 1.0.0
     */
    function init() {
        // activation / deactivation hook
        register_activation_hook( __FILE__, array( $this, 'on_activated' ) );
        register_deactivation_hook( __FILE__, array( $this, 'on_deactivated' ) );

        // register new custom tables
        add_action( 'init', array( $this, 'register_tables' ) );

        // register rest API
        add_action( 'rest_api_init', array( $this, 'register_rest_api' ) );
    }

    /**
     * Do when plugin is activated.
     * 
     * @since 1.0.0
     */
    function on_activated() {}

    /**
     * Do when plugin is deactivated.
     * 
     * @since 1.0.0
     */
    function on_deactivated() {}

    /**
     * Register new custom tables.
     * 
     * @uses $wpdb
     * @uses get_option()
     * @uses update_option()
     * @uses dbDelta()
     * 
     * @since 1.0.0
     */
    function register_tables() {
        global $wpdb;

        $installed_tbl_version = get_option( 'me_auth_example_tbl_version', 0 );
        $current_tbl_version   = 1.0;
        $charset_collate       = $wpdb->get_charset_collate();

        if ( $current_tbl_version > $installed_tbl_version ) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';

            // setup queries
            $queries = array(
                "CREATE TABLE {$wpdb->prefix}me_auth_example_users (
                    user_id BIGINT NOT NULL AUTO_INCREMENT,
                    email VARCHAR(50) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    fullname VARCHAR(50) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    PRIMARY KEY (user_id)
                )"
            );

            // execute queries
            dbDelta( $queries );

            // update table version
            update_option( 'me_auth_example_tbl_version', $current_tbl_version, false );
        }
    }

    /**
     * Create token.
     * 
     * @uses wp_parse_args()
     * @param array $payload
     * @return array $tokens
     * 
     * @since 1.0.0
     */
    function generate_token( $payload ) {
        require_once ME_AUTH_EXAMPLE_PLUGIN_DIR . 'vendor/autoload.php';
        $current_time = time();
        $jwt_exp      = $current_time + ( 60 * 30 );
        $jwt_token    = \Firebase\JWT\JWT::encode( wp_parse_args( $payload, array(
            'iat' => $current_time,
            'exp' => $jwt_exp
        ) ), $this->token_secret );

        // create refresh token
        $refrest_exp   = $current_time + ( 60 * 60 );
        $refresh_token = \Firebase\JWT\JWT::encode( wp_parse_args( $payload, array(
            'iat' => $current_time,
            'exp' => $refrest_exp
        ) ), $this->token_secret );

        // return token
        return array(
            'access_token'  => $jwt_token,
            'exp'           => $jwt_exp,
            'refresh_token' => $refresh_token,
            'refresh_exp'   => $refrest_exp
        );
    }

    /**
     * Middleware - verify token.
     * 
     * @since 1.0.0
     */
    function verify_token( $request ) {
        $headers = getallheaders();
        if ( ! empty( $request->get_header( 'Authorization' ) ) ) {
            $auth_header = $request->get_header( 'Authorization' );
        } else if ( ! empty( $headers['Authorization'] ) ) {
            $auth_header = $headers['Authorization'];
        } else {
            return new WP_Error( 'verify_token', 'Invalid token.', array( 'status' => 401 ) );
        }
        $auth = array_map( 'trim', explode( 'Bearer', $auth_header ) );

        // if empty token
        if ( ! isset( $auth[1] ) || empty( $auth[1] ) ) {
            return new WP_Error( 'verify_token', 'Invalid token.', array( 'status' => 401 ) );
        }

        // verify token by get payload
        $payload = $this->get_payload( $auth[1] );
        if ( empty( $payload ) ) {
            return new WP_Error( 'verify_token', 'Invalid token.', array( 'status' => 401 ) );
        }
        return true;
    }

    /**
     * Get payload from token.
     * 
     * @param string $token
     * @return array $payload
     * 
     * @since 1.0.0
     */
    function get_payload( $token ) {
        require_once ME_AUTH_EXAMPLE_PLUGIN_DIR . 'vendor/autoload.php';
        try {
            $decoded_token = \Firebase\JWT\JWT::decode( $token, $this->token_secret, array( 'HS256' ) );
            $payload       = (array) $decoded_token;
            return $payload;
        } catch ( UnexpectedValueException $e ) {
            return array();
        }
    }

    /**
     * Register Rest API.
     * 
     * @since 1.0.0
     */
    function register_rest_api() {
        $this->route_user_register();
        $this->route_user_auth();
        $this->route_user_refresh_token();

        // an example route protected by access token
        $this->route_get_posts();
    }

    /**
     * Register route: User register.
     * 
     * @uses current_time()
     * @uses register_rest_route()
     * @uses rest_ensure_response()
     * 
     * @since 1.0.0
     */
    function route_user_register() {
        // https://yourdomain.com/wp-json/me-auth-example/user/register
        register_rest_route( $this->api_namespace, '/user/register', array(
            'methods' => WP_REST_Server::CREATABLE,
            'args'    => array(
                'email' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                ),
                'fullname' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                ),
                'password' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                ),
                'repassword' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                )
            ),
            'permission_callback' => function() { return true; },
            'callback' => function( $request ) {
                $email      = $request->get_param( 'email' );
                $fullname   = $request->get_param( 'fullname' );
                $password   = $request->get_param( 'password' );
                $repassword = $request->get_param( 'repassword' );

                // user validation
                if ( empty( $email ) || ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
                    return new WP_Error( 'user_register', 'Invalid email.', array( 'status' => 400 ) );
                }
                if ( empty( $fullname ) ) {
                    return new WP_Error( 'user_register', 'Empty fullname.', array( 'status' => 400 ) );
                }
                if ( empty( $password ) ) {
                    return new WP_Error( 'user_register', 'Invalid password.', array( 'status' => 400 ) );
                }
                if ( empty( $repassword ) || $repassword != $password ) {
                    return new WP_Error( 'user_register', 'Invalid confirm password.', array( 'status' => 400 ) );
                }

                // check email in database
                global $wpdb;
                $find_user = $wpdb->get_results(
                    "SELECT user_id FROM {$wpdb->prefix}me_auth_example_users WHERE email = '{$email}'"
                );
                if ( $wpdb->last_error != '' ) {
                    return new WP_Error( 'user_register', 'Failed to find user.', array( 'status' => 400 ) );
                }
                if ( ! empty( $find_user ) ) {
                    return new WP_Error( 'user_register', 'Email already exists.', array( 'status' => 400 ) );
                }

                // generate personal access token
                $access_token = md5( 'user.' . $email . 'registered' );

                // create user
                $wpdb->insert( $wpdb->prefix . 'me_auth_example_users', array(
                    'email'      => $email,
                    'password'   => md5( $password ),
                    'fullname'   => $fullname,
                    'status'     => 'active',
                    'created_at' => current_time( 'mysql' ),
                    'updated_at' => current_time( 'mysql' )
                ), array(
                    '%s', '%s', '%s', '%s', '%s', '%s'
                ) );

                if ( $wpdb->last_error != '' ) {
                    return new WP_Error( 'user_register', 'Failed to create user.', array( 'status' => 400 ) );
                }
                return rest_ensure_response( array(
                    'status'  => true,
                    'code'    => 200,
                    'message' => 'User created.',
                    'data'    => array(
                        'email'    => $email,
                        'fullname' => $fullname
                    )
                ) );
            }
        ) );
    }

    /**
     * Register route: User auth.
     * 
     * @uses register_rest_route()
     * @uses rest_ensure_response()
     * 
     * @since 1.0.0
     */
    function route_user_auth() {
        // https://yourdomain.com/wp-json/me-auth-example/user/auth
        register_rest_route( $this->api_namespace, '/user/auth', array(
            'methods' => WP_REST_Server::CREATABLE,
            'args'    => array(
                'email' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                ),
                'password' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                )
            ),
            'permission_callback' => function() { return true; },
            'callback' => function( $request ) {
                $email    = $request->get_param( 'email' );
                $password = $request->get_param( 'password' );

                // user validation
                if ( empty( $email ) || ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
                    return new WP_Error( 'user_auth', 'Invalid email.', array( 'status' => 400 ) );
                }
                if ( empty( $password ) ) {
                    return new WP_Error( 'user_auth', 'Invalid password.', array( 'status' => 400 ) );
                }

                // find user in database
                global $wpdb;
                $hash_pass = md5( $password );
                $find_user = $wpdb->get_results(
                    "SELECT user_id, fullname FROM {$wpdb->prefix}me_auth_example_users WHERE email = '{$email}' AND password = '{$hash_pass}'"
                );
                if ( $wpdb->last_error != '' ) {
                    return new WP_Error( 'user_auth', 'Failed to find user.', array( 'status' => 400 ) );
                }
                if ( empty( $find_user ) ) {
                    return new WP_Error( 'user_auth', 'Invalid email/password.', array( 'status' => 400 ) );
                }

                // create token
                $generated_token = $this->generate_token( array(
                    'uid'  => md5( $find_user[0]->user_id ),
                    'sub'  => $find_user[0]->user_id,
                    'iss'  => $email,
                    'name' => $find_user[0]->fullname
                ) );

                // return response
                return rest_ensure_response( $generated_token );
            }
        ) );
    }

    /**
     * Register route: User refresh token.
     * 
     * @uses register_rest_route()
     * @uses rest_ensure_response()
     * 
     * @since 1.0.0
     */
    function route_user_refresh_token() {
        // https://yourdomain.com/wp-json/me-auth-example/user/refresh
        register_rest_route( $this->api_namespace, '/user/refresh', array(
            'methods' => WP_REST_Server::CREATABLE,
            'args'    => array(
                'refresh_token' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                )
            ),
            'permission_callback' => function() { return true; },
            'callback' => function( $request ) {
                // get refresh token
                $refresh_token = $request->get_param( 'refresh_token' );
                if ( empty ( $refresh_token ) ) {
                    return new WP_Error( 'user_refresh', 'Invalid refresh token.', array( 'code' => 401 ) );
                }

                // verify token
                $payload = $this->get_payload( $refresh_token );
                if ( empty( $payload ) ) {
                    return new WP_Error( 'user_refresh', 'Invalid refresh token.', array( 'code' => 401 ) );
                }

                // return new token
                return rest_ensure_response( $this->generate_token( $payload ) );
            }
        ) );
    }

    /**
     * Register route: Get posts.
     * 
     * @uses get_posts()
     * @uses register_rest_route()
     * @uses rest_ensure_response()
     * 
     * @since 1.0.0
     */
    function route_get_posts() {
        // https://yourdomain.com/wp-json/me-auth-example/post/gets
        register_rest_route( $this->api_namespace, '/post/gets', array(
            'methods' => WP_REST_Server::READABLE,
            'args'    => array(
                'refresh_token' => array(
                    'type'     => 'string',
                    'required' => true,
                    'default'  => ''
                )
            ),
            'permission_callback' => array( $this, 'verify_token' ),
            'callback' => function( $request ) {
                $posts = get_posts( array(
                    'post_status'    => 'publish',
                    'post_type'      => 'post',
                    'posts_per_page' => 10
                ) );
                return rest_ensure_response( $posts );
            }
        ) );
    }
}

/**
 * RUN CONTROLLER.
 */
$controller = new Me_Auth_Example();
$controller->init();
