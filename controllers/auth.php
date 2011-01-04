<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Auth extends CI_Controller {

    function __construct()
    {
        parent::__construct();

        $this->load->library('form_validation');
        $this->load->model('radius');
        $this->load->helper('url');
    }

    //redirect if needed, otherwise display the user list
    function index() 
    {
    	if (!$this->ion_auth->logged_in()) {
	    	//redirect them to the login page
			redirect('auth/login', 'refresh');
    	}
    	elseif (!$this->ion_auth->is_admin()) {
    		//redirect them to the home page because they must be an administrator to view this
			redirect($this->config->item('base_url'), 'refresh');
    	} else {
	        //set the flash data error message if there is one
		$this->view_data['head_title'] = 'Breezes :: Indice';

    		//list the users
    		$this->view_data['users'] = $this->ion_auth->get_users_array();
    		$this->load->view('auth/index', $this->view_data);
    	}
    }
    
    //log the user in
    function login() 
    {

	if ($this->ion_auth->logged_in()) { // if user is already logged in
		// Added By Henry Mata
		// Here is the 'redirect to requested page after login' thing.
		// We test if the visitor was denied and sent to the login form.
		$requested_page = $this->session->flashdata('requested_page');
		if ( $requested_page != '' ) {
		    redirect($requested_page);
		} else {
		    redirect($this->config->item('base_url'), 'refresh');
		}
	}

	$this->view_data['head_title'] = 'Breezes :: Iniciar Sesión';

        //validate form input
	$this->form_validation->set_rules('email', 'Correo Electrónico', 'required|valid_email');
	$this->form_validation->set_rules('password', 'Contraseña', 'required');

        if ($this->form_validation->run() == true) { //check to see if the user is logging in
		//check for "remember me"
		$remember = ($this->input->post('remember') == 1);

		if ($this->ion_auth->login($this->input->post('email'), $this->input->post('password'), $remember)) { //if the login is successful

			// Added By Henry Mata
			// Here is the 'redirect to requested page after login' thing.
			// We test if the visitor was denied and sent to the login form.
			$requested_page = $this->session->flashdata('requested_page');
			if ( $requested_page != '' ) {
			    redirect($requested_page);
			}

			// Added By Henry Mata
			// if no page was requested before, let's redirect the user
			// according to his role
			switch ($this->session->userdata('group'))
			{
			    case ('admin'):
				// On success redirect admin to default page
				redirect($this->config->item('admin_login_success_action','ion_auth')); break;
			    default:
				// On success redirect user to default page
				redirect($this->config->item('user_login_success_action','ion_auth')); break;
			}
	        }
	        else {  // if the login was un-successful, redirect them back to the login page
			// Added By Henry Mata
			// We have to keep the page info once again in case of
			// the user is still denied on the requested page.
			// (otherwise the 'already logged in' message is displayed)
			$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
			$this->session->keep_flashdata('requested_page');
                        redirect('auth/login','refresh');
	        }
        }
		else {  //the user is not logging in so display the login page

			//set the flash data error message if there is one
			$this->view_data['email']      = array('name'    => 'email',
							  'id'      => 'email',
							  'type'    => 'text',
							  'value'   => $this->form_validation->set_value('email'),
                                             );
			$this->view_data['password']   = array('name'    => 'password',
							  'id'      => 'password',
							  'type'    => 'password',
                                             );

			// Added By Henry Mata
			// We have to keep the page info once again in case of
			// the user is still denied on the requested page.
			// (otherwise the 'already logged in' message is displayed)
			$this->session->keep_flashdata('requested_page');
			$this->load->view('auth/login', $this->view_data);
		}
    }

    //log the user out
	function logout() 
	{
	$this->view_data['head_title'] = 'Breezes :: Cerrar Sesión';
        
        //log the user out
        $logout = $this->ion_auth->logout();
			    
        //redirect them back to the page they came from
        redirect('auth/login', 'refresh');
    }
    
    //change password
	function change_password() 
	{	    

	    if (!$this->ion_auth->logged_in()) {
		redirect('auth/login', 'refresh');
	    }

	    $this->form_validation->set_rules('old_password', 'Contraseña actaul', 'required');
	    $this->form_validation->set_rules('new_password', 'Contraseña nueva', 'required|min_length['.$this->config->item('min_password_length', 'ion_auth').']|max_length['.$this->config->item('max_password_length', 'ion_auth').']|matches[new_password_confirm]');
	    $this->form_validation->set_rules('new_password_confirm', 'Confirmar contraseña', 'required');

	    $user = $this->ion_auth->get_user($this->session->userdata('user_id'));

	    if ($this->form_validation->run() == false) { //display the form

		// head title
		$this->view_data['head_title'] = 'Breezes :: Cambiar contraseña';

	        //set the flash data error message if there is one
	        $this->view_data['old_password']           = array('name'    => 'old_password',
		                                               	  'id'      => 'old_password',
		                                              	  'type'    => 'password',
		                                                 );
	        $this->view_data['new_password']           = array('name'    => 'new_password',
		                                               	  'id'      => 'new_password',
		                                              	  'type'    => 'password',
		                                                 );
        	$this->view_data['new_password_confirm']   = array('name'    => 'new_password_confirm',
                                                      	  'id'      => 'new_password_confirm',
                                                      	  'type'    => 'password',
        												 );
        	$this->view_data['user_id']                = array('name'    => 'user_id',
                                                      	  'id'      => 'user_id',
                                                      	  'type'    => 'hidden',
        												  'value'   => $user->id,
        												 );
	        
        	//render
        	$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
        	$this->load->view('auth/change_password', $this->view_data);
	    }
	    else {
	        $identity = $this->session->userdata($this->config->item('identity', 'ion_auth'));
	        
	        $change = $this->ion_auth->change_password($identity, $this->input->post('old_password'), $this->input->post('new_password'));
		
    		if ($change) { //if the password was successfully changed
                       $this->messages->redirect($this->ion_auth->messages(),MESSAGE_SUCCESS,'/auth/logout');
    		}
    		else {
			$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
			redirect('/auth/change_password','refresh');
    		}
	    }
	}
	
	//forgot password
	function forgot_password() 
	{
		$this->form_validation->set_rules('email', 'Correo electrónico', 'required|valid_email');
	    if ($this->form_validation->run() == false) {

	    	//setup style
		$this->view_data['head_title'] = 'Breezes :: Recuperar Contraseña';

	    	//setup the input
	    	$this->view_data['email'] = array('name'    => 'email',
                                                  'id'      => 'email',
        						    );
	    	//set any errors and display the form
    		$this->load->view('auth/forgot_password', $this->view_data);
	    }
	    else {
	        //run the forgotten password method to email an activation code to the user
			$forgotten = $this->ion_auth->forgotten_password($this->input->post('email'));
			
			if ($forgotten) { //if there were no errors
                                $this->messages->redirect($this->ion_auth->messages(),MESSAGE_INFO,'/auth/login');
			}
			else {
				$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
				redirect('/auth/forgot_password','refresh');
			}
	    }
	}
	
	//reset password - final step for forgotten password
	public function reset_password($code) 
	{
		$reset = $this->ion_auth->forgotten_password_complete($code);
		
		if ($reset) {  //if the reset worked then send them to the login page
                        $this->messages->redirect($this->ion_auth->messages(),MESSAGE_INFO,'/auth/login');
		}
		else { //if the reset didnt work then send them back to the forgot password page
                        $this->messages->redirect($this->ion_auth->errors(),MESSAGE_ERROR,'/auth/forgot_password');
		}
	}

	//activate the user
	function activate($id, $code=false) 
	{        
		$activation = $this->ion_auth->activate($id, $code);
		
        if ($activation) {
			//redirect them to the auth page
                        $this->messages->redirect($this->ion_auth->messages(),MESSAGE_INFO,'/auth');
        }
        else {
			//redirect them to the forgot password page
                        $this->messages->redirect($this->ion_auth->errors(),MESSAGE_ERROR,'/auth/forgot_password');
        }
    }
    
    //deactivate the user
	function deactivate($id = NULL) 
	{
		// no funny business, force to integer
		$id = (int) $id;

		$this->form_validation->set_rules('confirm', 'confirmation', 'required');
		$this->form_validation->set_rules('id', 'user ID', 'required|is_natural');
				
		if ( $this->form_validation->run() == FALSE )
		{
			// insert csrf check
		$this->view_data['head_title'] = 'Breezes :: Desactivar Usuario';
		$this->view_data['csrf']	=	$this->_get_csrf_nonce();
		$this->view_data['user']	=	$this->ion_auth->get_user($id);
    		$this->load->view('auth/deactivate_user', $this->view_data);
		}
		else
		{
			// do we really want to deactivate?
			if ( $this->input->post('confirm') == 'yes' )
			{
				// do we have a valid request?
				if ( $this->_valid_csrf_nonce() === FALSE || $id != $this->input->post('id') )
				{
					show_404();
				}

				// do we have the right userlevel?
				if ( $this->ion_auth->logged_in() && $this->ion_auth->is_admin() )
				{
					$this->ion_auth->deactivate($id);
				}
			}
	
			//redirect them back to the auth page
			redirect('auth/login','refresh');
		}
    }
    
    //create a new user
	function create_user() 
	{  
        $this->view_data['title'] = "Create User";
              
		if (!$this->ion_auth->logged_in() || !$this->ion_auth->is_admin()) {
			redirect('auth/login', 'refresh');
		}
		
        //validate form input
    	$this->form_validation->set_rules('first_name', 'First Name', 'required|xss_clean');
    	$this->form_validation->set_rules('last_name', 'Last Name', 'required|xss_clean');
    	$this->form_validation->set_rules('email', 'Email Address', 'required|valid_email');
//    	$this->form_validation->set_rules('phone1', 'First Part of Phone', 'required|xss_clean|min_length[3]|max_length[3]');
//    	$this->form_validation->set_rules('phone2', 'Second Part of Phone', 'required|xss_clean|min_length[3]|max_length[3]');
//    	$this->form_validation->set_rules('phone3', 'Third Part of Phone', 'required|xss_clean|min_length[4]|max_length[4]');
//    	$this->form_validation->set_rules('company', 'Company Name', 'required|xss_clean');
    	$this->form_validation->set_rules('password', 'Password', 'required|min_length['.$this->config->item('min_password_length', 'ion_auth').']|max_length['.$this->config->item('max_password_length', 'ion_auth').']|matches[password_confirm]');
    	$this->form_validation->set_rules('password_confirm', 'Password Confirmation', 'required');

        if ($this->form_validation->run() == true) {
            $username  = strtolower($this->input->post('first_name')).' '.strtolower($this->input->post('last_name'));
            $email     = $this->input->post('email');
            $password  = $this->input->post('password');
        	
            $additional_data = array('first_name' => $this->input->post('first_name'),
             				        'last_name'  => $this->input->post('last_name'),
        					'company'    => $this->input->post('company'),
        					'phone'      => $this->input->post('phone1') .'-'. $this->input->post('phone2') .'-'. $this->input->post('phone3'),
        				       );
        }
        if ($this->form_validation->run() == true && $this->ion_auth->register($username,$password,$email,$additional_data)) { //check to see if we are creating the user
                //redirect them back to the admin page
                $this->messages->redirect('User Created',MESSAGE_INFO,'/auth');

		} 
		else { //display the create user form
	        //set the flash data error message if there is one
                $this->view_data['head_title'] = 'Breezes :: Crear Usuario';
		$this->view_data['first_name']          = array('name'   => 'first_name',
		                                              'id'      => 'first_name',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('first_name'),
		                                             );
		$this->view_data['last_name']           = array('name'   => 'last_name',
		                                              'id'      => 'last_name',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('last_name'),
		                                             );
		$this->view_data['email']              = array('name'    => 'email',
		                                              'id'      => 'email',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('email'),
		                                             );
		$this->view_data['company']            = array('name'    => 'company',
		                                              'id'      => 'company',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('company'),
		                                             );
		$this->view_data['phone1']             = array('name'    => 'phone1',
		                                              'id'      => 'phone1',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('phone1'),
		                                             );
		$this->view_data['phone2']             = array('name'    => 'phone2',
		                                              'id'      => 'phone2',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('phone2'),
		                                             );
		$this->view_data['phone3']             = array('name'    => 'phone3',
		                                              'id'      => 'phone3',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('phone3'),
		                                             );
		$this->view_data['password']           = array('name'    => 'password',
		                                              'id'      => 'password',
		                                              'type'    => 'password',
		                                              'value'   => $this->form_validation->set_value('password'),
		                                             );
		$this->view_data['password_confirm']   = array('name'    => 'password_confirm',
                                                      'id'      => 'password_confirm',
                                                      'type'    => 'password',
                                                      'value'   => $this->form_validation->set_value('password_confirm'),
                                                     );
		$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
		$this->load->view('auth/create_user', $this->view_data);
		}
    }
    
    //register new user
	function register()
	{

        //validate form input
        $this->form_validation->set_rules('first_name', 'Nombre', 'required|xss_clean');
        $this->form_validation->set_rules('last_name', 'Apellido', 'required|xss_clean');
        $this->form_validation->set_rules('email', 'Correo electronico', 'required|valid_email');
        $this->form_validation->set_rules('password', 'Contraseña', 'required|min_length['.$this->config->item('min_password_length', 'ion_auth').']|max_length['.$this->config->item('max_password_length', 'ion_auth').']|matches[password_confirm]');
        $this->form_validation->set_rules('password_confirm', 'Confirmar contraseña', 'required');

        if ($this->form_validation->run() == true) {

            $username  = $this->input->post('email');
            $email     = $this->input->post('email');
            $password  = $this->input->post('password');

            $additional_data = array('first_name' => $this->input->post('first_name'),
             			     'last_name'  => $this->input->post('last_name')
					);
            if ($this->ion_auth->register($username,$password,$email,$additional_data)) { //check to see if we are creating the user
                $this->radius->adduser($email,$password,FALSE,FALSE,CallingStationID(TRUE));
                $this->ion_auth->login($email,$password, TRUE);

                //redirect them back to home page
                $this->messages->redirect("$email ha sido registrado satisfactoriamente",MESSAGE_SUCCESS,'/');
            } else {
			$this->messages->set($this->ion_auth->errors(),MESSAGE_ERROR,TRUE);
			redirect('auth/register','refresh');
            }
	}
	else { //display the create user form
	        // head title
		$this->view_data['head_title'] = 'Breezes :: Registrar cuenta de Usuario';

	        //set the flash data error message if there is one

		$this->view_data['first_name']          = array('name'   => 'first_name',
		                                              'id'      => 'first_name',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('first_name'),
		                                             );
		$this->view_data['last_name']           = array('name'   => 'last_name',
		                                              'id'      => 'last_name',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('last_name'),
		                                             );
		$this->view_data['email']              = array('name'    => 'email',
		                                              'id'      => 'email',
		                                              'type'    => 'text',
		                                              'value'   => $this->form_validation->set_value('email'),
		                                             );
		$this->view_data['password']           = array('name'    => 'password',
		                                              'id'      => 'password',
		                                              'type'    => 'password',
		                                              'value'   => $this->form_validation->set_value('password'),
		                                             );
		$this->view_data['password_confirm']   = array('name'    => 'password_confirm',
		                                              'id'      => 'password_confirm',
		                                              'type'    => 'password',
		                                              'value'   => $this->form_validation->set_value('password_confirm'),
                                                     );
                $this->messages->set($this->ion_auth->errors(), MESSAGE_ERROR, TRUE);
		$this->load->view('auth/register', $this->view_data);
		}
    }
    function _get_csrf_nonce()
    {
		$this->load->helper('string');
		$key	= random_string('alnum', 8);
		$value	= random_string('alnum', 20);
		$this->session->set_flashdata('csrfkey', $key);
		$this->session->set_flashdata('csrfvalue', $value);

		return array($key=>$value);
	}
	
	function _valid_csrf_nonce()
	{
			if ( $this->input->post($this->session->flashdata('csrfkey')) !== FALSE &&
				 $this->input->post($this->session->flashdata('csrfkey')) == $this->session->flashdata('csrfvalue'))
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}
	}
}
