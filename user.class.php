<?php

/*
 * users.class.php
 * Description of User - Users of the system, contains methods for user management, permisisons checks, etc.
 * Globals/Constants defined in scope:
 *
 * define('COOKIE_ID',         sha1($_SERVER['SERVER_NAME']));
 * define('AUTH_SALT',         'Salt for authentication cookies');
 * define('AUTH_KEY',          'Key for authentication cookies');
 * define('SESSION_LENGTH',    strtotime('+1 day'));
 * define('DEFAULT_TIMEZONE',  'America/New_York');
 *
 * global $db = new PDO();  //this is already authenticated at this file.
 * global $table = array('table_names');
 *
 * @author Max BrownGold
 */
class User {
    
    public $id, $username, $email, $firstname, $lastname;
    private $password, $timezone, $publication;
    /**
     * @param array|stdObj $data Data to convert to user object
     */
    public function __construct($data) {
        $data = (object)$data;
        $this->id = empty($data->id)?0:$data->id;
        $this->username = empty($data->username)?false:$data->username;
        $this->email = isset($data->email) && is_email($data->email)?$data->email: "";
        $this->firstname = isset($data->firstname)?$data->firstname:"";
        $this->lastname = isset($data->lastname)?$data->lastname:"";
        $this->password = isset($data->password)?$data->password:false;
        $this->timezone = isset($data->timezone) && isValidTimezone($data->timezone)?$data->timezone:DEFAULT_TIMEZONE;
        $this->publication = isset($data->publication)?is_array($data->publication)?$data->publication:explode('|',$data->publication):array();
    }
    public function import_new_data($data){
        foreach($data as $key=>$value){
            if($key == 'password' || $key == 'username') continue;  //don't update password from here, never update username.
            if($key == 'publication' && !is_array($value)) $value = array($value);
            $this->{$key} = $value;
        }
        $this->save();
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @param int $id
     * @return User|boolean
     */
    public static function fromID($id){
        global $db, $table;
        self::selectUserDB();
        $sql = "SELECT * FROM $table->users WHERE id = :id LIMIT 1";
        $stmt = $db->prepare($sql);
        $stmt->execute(array('id'=>$id));
        $userdata = $stmt->fetchall(PDO::FETCH_OBJ);
        return empty($userdata)?false:new self($userdata[0]);
    }
    /**
     * @global PDO $db;
     * @global stdClass $table
     * @return Array
     */
    public static function all_users(){
        global $db, $table;
        self::selectUserDB();
        $sql = "SELECT * FROM $table->users";
        $stmt = $db->prepare($sql);
        $stmt->execute();
        $users = $stmt->fetchAll(PDO::FETCH_OBJ);
        $user_array = array();
        foreach($users as $user){
            $user_array[] = new self($user);
        }
        return $user_array;
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @param string $username
     * @return User|boolean
     */
    public static function fromUsername($username){
        global $db, $table;
        self::selectUserDB();
        $sql = "SELECT * FROM $table->users WHERE username = :username LIMIT 1";
        $stmt = $db->prepare($sql);
        $stmt->execute(array($username));
        $userdata = $stmt->fetchall(PDO::FETCH_OBJ);
        return empty($userdata)?false:new self($userdata[0]);
    }
    /**
     * 
     * @return Publication|boolean
     */
    public function load_default_publication(){
        $id = $this->is_admin()?$this->publication[1]:$this->publication[0];
        if(empty($id) && $this->is_admin()){
            $p = Publication::get_all();
            $pub = $p[0];
        }
        else $pub = Publication::fromID($this->publication[0]);
        if($pub)
            $pub->set_to_current ();
        else return false;
        
        return $pub;
    }
    /**
     * 
     * @param string $username Username trying login
     * @param string $password Plain Text password trying to login
     * @return boolean Returns true on successful login, fals on failed login.
     */
    public static function login($username, $password){
        $user = self::fromUsername($username); //get user object for attempted login
        
        if($user->verify_password($password)){
            $user->create_auth_cookie();
            return true;
        }
        else return false;
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @param string $username
     * @return int 0/1
     */
    public static function name_exists($username){
        global $db, $table;
        self::selectUserDB();
        $stmt = $db->prepare("SELECT id FROM $table->users WHERE username=:username LIMIT 1");
        $stmt->execute(array('username'=>$username));
        return $stmt->rowCount();
    }
    /**
     * 
     * @param string $password Password to be verified
     * @return string|bool Returns the hashed password on pass and false on fail.
     */
    public function verify_password($password){
        return password_verify($password, $this->password)?$this->password:false;
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @param string $newPassword
     * @return string hash of new password
     */
    public function updatePassword($newPassword){
        $this->password = password_hash($newPassword, PASSWORD_DEFAULT);
        global $db, $table;
        $stmt = $db->prepare("UPDATE $table->users SET password=:password WHERE id=:id");
        $stmt->execute(array('password'=>$this->password, 'id'=>$this->id));
        return $this->password;
        
    }
    /**
     * 
     * @param string $capability
     * @return boolean
     */
    public function can($capability=false, $publication = false){
        if($this->publication[0] == 'all') return true;
        else return in_array($publication, $this->publication);
        
        /****THIS IS FOR FUTURE ADDITION OF ROLE SYSTEM
        $role = Role::fromName($this->role);
        return $role?$role->can($capability):false;
        */
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @return User|boolean Returns false if no user is logged in otherwise returns current user object
     */
    public static function is_logged_in(){
        if(!isset($_COOKIE[SYSTEM_PREFIX . COOKIE_ID])) return false;

        $cookie = explode('|', $_COOKIE[SYSTEM_PREFIX . COOKIE_ID]);
        if($cookie[1] > time()){self::logout(); return false;}
        
        $user = self::fromUsername($cookie[0]);
        $cookie = $user->create_auth_cookie(false, $cookie[1]);

        return($cookie == $_COOKIE[SYSTEM_PREFIX . COOKIE_ID])?$user:false;

    }
    /**
     * Function logs out current user.
     * @return void
     */
    public static function logout(){
        if(isset($_COOKIE[SYSTEM_PREFIX . COOKIE_ID])){
            unset($_COOKIE[SYSTEM_PREFIX . COOKIE_ID]);
            setcookie(SYSTEM_PREFIX . COOKIE_ID, null);
        }
        return;
    }
    /**
     * 
     * @param type $set
     * @param type $expiration
     * @return type
     */
    private function create_auth_cookie($set = true, $expiration = SESSION_LENGTH){
        $salt = AUTH_SALT;

        if(!$expiration)$expiration = strtotime("+1 day");
        $key = sha1($this->username . $expiration . substr($this->password, 8, 4) . $salt);
        $hash = hash_hmac('sha1', $this->username . $expiration, $key);
        $cookie = $this->username . '|' . $expiration . '|'. $hash;
        if($set)$_COOKIE[SYSTEM_PREFIX . COOKIE_ID] = $cookie;
        return $set?setcookie(SYSTEM_PREFIX . COOKIE_ID, $cookie):$cookie;
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @param string $newPassword The password that should be set.
     * @return string Returns hash of input password
     */
    public function setPassword($newPassword){
        $hash = password_hash($newPassword, PASSWORD_DEFAULT);
        
        global $db, $table;
        self::selectUserDB();
        $stmt = $db->prepare("UPDATE $table->users SET `password` = :password WHERE id= :id");
        if(!$this->id)
            $this->save();        
        
        $stmt->execute(array('password'=>$hash, 'id'=>$this->id));
        $this->password = $hash;
        
        return $hash;
    }
    /**
     * 
     * @global PDO $db
     * @global stdClass $table
     * @return int Returns user id of the saved user
     */
    public function save(){
        global $db, $table;
        self::selectUserDB();
        $fields = $placeholders = $update = '';
        $values = array();
        foreach($this as $key => $value){
            if($key == 'password' || $key == 'id') continue; //don't set the password in the save method, use updatePassword() instead to prevent unhashed passwords from making it to the db.
            if($key == 'publication') $value = implode('|', $value);
            $fields .= "`$key`,";
            $placeholders .= ":$key,";
            $update .= "`$key`=:$key,";
            $values[$key] = $value;
        }
       
       
       
        
        if(!$this->id){            
            $stmt = $db->prepare("INSERT INTO $table->users ($fields) VALUES($placeholders)");
            
        }
        else{
            $stmt = $db->prepare("UPDATE $table->users SET $update WHERE id = :id");
            $values['id'] = $this->id;
        }
        
        $stmt->execute($values);
        if(!$this->id) $this->id = $db->lastInsertID();
        
        return $this->id;        
    }
    /**
     * 
     * @return string
     */
    public function getTimezone(){
        return $this->timezone;
    }
    /**
     * 
     * @return bool
     */
    public function is_admin(){
        return $this->publication[0] == 'all';
    }
    /**
     * 
     * @param string $property
     * @return array
     */
    public function getPublication($property = 'id'){
        switch($property){
            case 'id':
            default:
                return $this->publication;
                break;
            case 'name':
            case 'title':
                if($this->publication[0]=='all') return array("All");
                $pubs = array();
                foreach($this->publication as $pub){
                    $pub_obj = Publication::fromID($pub);
                    if($pub_obj)$pubs[] = $pub_obj->title;
                }
                return $pubs;
                break;
        }
    }
    public function setTimezone(){
        if(isValidTimezone($this->timezone))
            date_default_timezone_set ($this->timezone);
    }
    /**
     * 
     * @global PDO $db
     * @return PDO::result
     */
    protected static function selectUserDB(){
        global $db;
        return $db->query("USE " . DB_USER);
    }
}
