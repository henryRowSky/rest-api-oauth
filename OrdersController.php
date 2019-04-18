<?php
App::uses('HttpSocket', 'Network/Http');
class OrdersController extends AppController {
	public $helpers = array ('Html','Form');
    public $name = 'Orders';
    // public $uses = array();
    public $components = array ('RequestHandler');
	public function beforeFilter() {
        parent::beforeFilter(); 
       $this->Auth->allow('add');
    }
	
	 public function beforeRender() {
        parent::beforeRender();
    }


    function admin_index() {
        $role=$this->role;

        if($role == 'store_admin') {
            return $this->redirect(array('controller' => 'stores', 'action' => 'index', 'admin' => false));
        } 

		if ($this->request->is(array('post', 'put'))) {
			
			// Get request data into a var
			$store = $this->request->data;

	        $options = array('conditions' => array('Stores.friendly_name' => $store['Stores']['name']), 'fields' => 'Stores.store_id');
	        $this->loadModel('Stores');
	        $store = null;
	       	$store = $this->Stores->find('first', $options);

			return $this->redirect('/admin/orders/view/' . $store['Stores']['store_id']);
		}



        
        $conds = array('fields' => array('Stores.store_id', 'Stores.friendly_name'));
        $this->loadModel('Stores');
        $stores = $this->Stores->find('all', $conds);
 
		// Format JSON string in a way jQuery UI autocomplete can use
		$acstr = '[';
		foreach ($stores as $v) {
			$acstr .= '"' . $v['Stores']['friendly_name'] . '", '; }
		$acstr .= ']';

		// Send list of companies for autocomplete
		$this->set('stores', $acstr);

        $this->set('title_for_layout', 'Open Orders');
    }




    function admin_view($store_id  ) {

        // Get values for store
        // To get SellerActive authorization value
        $conds = array('conditions' => array('Stores.store_id' => $store_id), 'fields' => array('Stores.friendly_name'));
        $this->loadModel('Stores');
        $store = $this->Stores->find('first', $conds);


        $this->set('store_id', $store_id);

        $this->set('title_for_layout', $store['Stores']['friendly_name'] . ' Open Orders');
    }




	
    // Function "listens" for WebHook payloads coming from WC Add/Update Order events 
	function add() {
		$this->layout = false;
		if($this->request->is('post')) {
			
			// Load array and json encode header values
			$headers = array(
							'user-agent'=>$this->request->header('user-agent'),
							'content-type'=>$this->request->header('content-type'),
							'x-wc-webhook-source'=>$this->request->header('x-wc-webhook-source'),
							'x-wc-webhook-topic'=>$this->request->header('x-wc-webhook-topic'), 
							'x-wc-webhook-resource'=>$this->request->header('x-wc-webhook-resource'),
							'x-wc-webhook-event'=>$this->request->header('x-wc-webhook-event'),
							'x-wc-webhook-signature'=>$this->request->header('x-wc-webhook-signature'),
							'x-wc-webhook-id'=>$this->request->header('x-wc-webhook-id'),
							'x-wc-webhook-delivery-id'=>$this->request->header('x-wc-webhook-delivery-id'), 
						);

			// Use Hook Source value from header
			// to determine Store source, then query for correct config values
			$hook_src = $headers['x-wc-webhook-source'];

			// Log hook source
			//CakeLog::write('info', 'Header values: ' . json_encode($headers));
			//CakeLog::write('info', 'SA Auth Value: ' . $sa_auth); 
			//CakeLog::write('info', 'Hooksource value: ' . $hook_src);

			// Get incoming payload
			$data = file_get_contents("php://input"); 
			// Log incoming payload
			CakeLog::write('info', 'incoming json test: ' . $data);			



			$conds = array('conditions' => array('Stores.wc_hook_source' => $hook_src), 'fields' => array('Stores.wc_created_secret', 'Stores.wc_updated_secret'));
			$this->loadModel('Stores');	
			$store = $this->Stores->find('first', $conds);
			// Only process orders if the Store is active
			//if($store['Stores']['active']==0) {}
			// WooCommerce Webhooks use different Secret for hash authorization depending on action (create|update)
			// Determine which event (created|updated) and assign secret key
			$wc_secret = '';
			switch($headers['x-wc-webhook-event']) {
				case 'created':
					$wc_secret = $store['Stores']['wc_created_secret'];
					break;
				case 'updated':
					$wc_secret = $store['Stores']['wc_updated_secret'];
					break;
			}
			

			// Create a hash value using the data payload and secret stored in local db
			// Compare output to signature provided by the POST header

			// Generate hash using payload and secret key
			$hash = hash_hmac('sha256', $data, $wc_secret, true);
			// Base64 encode the hash value
			$hashBase64 = base64_encode($hash);
			// Get incoming header signature for authorization
			$signature = $headers['x-wc-webhook-signature'];			
			
			if($hashBase64 == $signature) {
				// Get data to pass to headers
				$data = $this->request->input('json_decode', true);
				$headers = json_encode($headers);
				$this->add_order($data, $headers);

				CakeLog::write('info', 'Test Order 1');	
			}
		}
	}


	function add_order($data=NULL, $headers=NULL) {
		$this->layout = false;
				
		// Create variables for values going into both orders and order_line_items DB tables
		// Or values needed the line_items array that are outside the scope of the main foreach loop
		$site_order_id = filter_var($data["order"]["order_number"], FILTER_VALIDATE_INT);

		if(empty($site_order_id)) {
			$site_order_id = rand(1, 9999);
		}


		$currency = filter_var($data["order"]["currency"], FILTER_SANITIZE_STRING);



		//$shipping_method_title = $data["order"]["shipping_lines"][0]["method_id"];

		if (isset($data["order"]["shipping_lines"][0])) {
			$shipping_price = filter_var($data["order"]["shipping_lines"][0]["total"], FILTER_VALIDATE_FLOAT);
			$shipping_service_ordered = filter_var($data["order"]["shipping_lines"][0]["method_title"], FILTER_SANITIZE_STRING);
			$shipping_carrier = filter_var($data["order"]["shipping_lines"][0]["method_id"], FILTER_SANITIZE_STRING);	
		} else {
			$shipping_price = 0;
			$shipping_service_ordered = '';
			$shipping_carrier = '';
		}




		$hook_src = $this->request->header('x-wc-webhook-source');
		$hook_event = $this->request->header('x-wc-webhook-event');
		$conds = array('conditions' => array('Stores.wc_hook_source' => $hook_src), 'fields' => array('Stores.store_id', 'Stores.sa_authkey', 'Stores.sa_site', 'Stores.convert_weight'));
		$this->loadModel('Stores');	
		$store = $this->Stores->find('first', $conds);
		// Authorization key value for store is
		$sa_auth = $store['Stores']['sa_authkey'];
		$store_id = $store['Stores']['store_id'];
		// Convert WooCommerce status string to value that SellerActive API accepts
		$status = filter_var($data["order"]["status"], FILTER_SANITIZE_STRING);
		switch($status) {
			case 'pending':
					$status = 'Pending';
				break;			
			case 'processing':
					$status = 'Unshipped';
				break;
			case 'on-hold':
				$status = 'OnHold';
				break;
			case 'completed':
				$status = 'Fulfilled'; // 'None';
				break;
			case 'refunded':
				$status = 'Returned';
				break;
			case 'failed':
				$status = 'Unfulfillable';
				break;
			case 'cancelled':
				$status = 'Cancelled';
				break;				
			default:
				$status = 'Unknown'; // 'None';
		}

		// Get value for incoming SellerActive site
		$sa_site = $store['Stores']['sa_site'];

		// Create Order array to insert into StellarAPI DB
		$orderData=array(
			// HTTP headers, JSON formatted
			'header_response' => $headers,
			// Column names match property names SellerActiveAPI is expecting
			'SiteOrderID' => $site_order_id,
			'Site' => $sa_site, //'SellerActiveWebApi',
			'OrderStatus' => $status,
			'DateOrdered' => date('Y-m-d H:i:s', strtotime($data["order"]["created_at"])),
			'Name' =>  filter_var($data["order"]["shipping_address"]["first_name"], FILTER_SANITIZE_STRING) . ' ' . filter_var($data["order"]["shipping_address"]["last_name"], FILTER_SANITIZE_STRING),
			'Address1' => filter_var($data["order"]["shipping_address"]["address_1"], FILTER_SANITIZE_STRING),
			'Address2' => filter_var($data["order"]["shipping_address"]["address_2"], FILTER_SANITIZE_STRING),
			'Address3' => '', //filter_var($data["order"]["shipping_address"]["company"], FILTER_SANITIZE_STRING),
			'City' => filter_var($data["order"]["shipping_address"]["city"], FILTER_SANITIZE_STRING),
			'StateOrRegion' => filter_var($data["order"]["shipping_address"]["state"], FILTER_SANITIZE_STRING),
			'Country' => filter_var($data["order"]["shipping_address"]["country"], FILTER_SANITIZE_STRING),
			'PostalCode' => filter_var($data["order"]["shipping_address"]["postcode"], FILTER_SANITIZE_STRING),
			'Phone' => filter_var($data["order"]["billing_address"]["phone"], FILTER_SANITIZE_STRING),
			'Email' => filter_var($data["order"]["billing_address"]["email"], FILTER_SANITIZE_STRING),
			'Note' => filter_var($data["order"]["note"], FILTER_SANITIZE_STRING),
			
			// Line item data as first received, JSON formatted
			'wc_order_details_json' => json_encode($data["order"]["line_items"]),
			// These fields come from WooCommerce, get saved in StellarAPI DB, but are not sent to StellarActive
			'customer_ip' => filter_var($data["order"]["customer_ip"], FILTER_SANITIZE_STRING),
			'customer_user_agent' => filter_var($data["order"]["customer_user_agent"], FILTER_SANITIZE_STRING),
			'customer_id' => filter_var($data["order"]["customer_id"], FILTER_VALIDATE_INT),
			'view_order_url' => filter_var($data["order"]["view_order_url"], FILTER_SANITIZE_STRING),
			'store_id' => $store_id,
		);
	
		$this->Order->create();
		$this->Order->save($orderData,false);
		// After Order Data is added to DB, remove header response value from array
		// No need to pass that info to SellerActive's API
		unset($orderData['header_response']);
		unset($orderData['wc_order_details_json']);
		unset($orderData['customer_ip']);
		unset($orderData['customer_user_agent']);
		unset($orderData['customer_id']);
		unset($orderData['view_order_url']);
		// Load array for new rows in the order_line_items table in db
		$this->loadModel('OrderLineItems');	
		// Array to hold all the line items
		$orderDetails = array();

		$lisku = null;
		// Loop thru each line item
		foreach($data["order"]["line_items"] as $item) {

			$lisku = filter_var($item["sku"], FILTER_SANITIZE_STRING);
			//CakeLog::write('info', 'StoreID: ' . $store_id . ' -> SKU: ' . $lisku);
			$wgt = $this->get_wc_product_wgt_by_sku($store_id, $lisku);


			if ($store['Stores']['convert_weight'] == 1) {
				$wgt = $this->oz_to_lbs($wgt);
			}

			//CakeLog::write('info', 'StoreID: ' . $store_id . ' -> SKU: ' . $lisku);
			

			$line_items = array(
				'SiteOrderID' => $site_order_id,
				'SiteItemID' => $item["id"],
				'OrderStatus' => $status,
				'DateShipped' => "",
				'SKU' => $lisku,
				'Title' => filter_var($item["name"], FILTER_SANITIZE_STRING),
				'QuantityOrdered' => filter_var($item["quantity"], FILTER_VALIDATE_INT),				
				'QuantityShipped' => 0,
				'QuantityUnfillable' => 0,
				'CurrencyISO' => $currency,
				'UnitPrice' => filter_var($item["price"], FILTER_VALIDATE_FLOAT),
				'UnitTax' => filter_var($item["total_tax"], FILTER_VALIDATE_FLOAT),
				'ShippingPrice' => $shipping_price,
				'ShippingTax' => 0,
				'ShippingDiscount' => 0,
				'GiftMessage' => "",
				'GiftWrapPrice' => 0,
				'GiftWrapTax' => 0,
				'ShippingServiceOrdered' => $shipping_service_ordered,
				'ShippingServiceActual' => $shipping_service_ordered,
				'ShippingTracking' => "",
				'ShippingActualWeight' => $wgt,
				'ShippingActualCharge' => 0,
				'ShippingCarrier' => $shipping_carrier,);
			// Save record of line item in database
			$this->OrderLineItems->create();
			$this->OrderLineItems->save($line_items, false);
			// SellerActive API is not expecting SiteOrderID so remove item
			unset($line_items['SiteOrderID']);
			// Then add the line item to orderDetails array
			array_push($orderDetails, $line_items);
		}
		// Add orderDetails array as new item OrderData array
		$orderData['OrderDetails'] = $orderDetails;

		CakeLog::write('info', 'Test Order 2');	
		// There is no reason to send info back about orders that are already fulfilled
		//if ($status != 'Fulfilled') {
			// Use Hook Source value provided in header
			// to get correct SellerActive Auth values
			// CURL the Order JSON to SellerActiveAPI
			$request_url = Configure::read('selleractive_api_order');
			$ch = curl_init($request_url);
			$meth = 'POST';
			switch($hook_event) {
				case 'updated':
					$meth = 'PUT';
					break;
			}

			

		    // SET the HTTP VERB type
		    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $meth);
	 
	 		 // Set CURL properties
			 curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); //  Uncomment to get more detailed response than 1|0
			 curl_setopt($ch, CURLOPT_VERBOSE, true);
			 curl_setopt($ch, CURLOPT_HEADER, true);
			 curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($orderData));
			 curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); 
			 // Set header values
			 curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', $sa_auth));
		
			// Execute CURL
			$response = curl_exec($ch);
			// Get info
			$info = curl_getinfo($ch);
			$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
			$header = substr($response, 0, $header_size);
			
			// Write troubleshooting output to debug log
			//CakeLog::write('info', 'SA Auth Value: ' . $sa_auth); 
			


			//CakeLog::write('info', 'Order Sent: ' . json_encode($orderData));
			CakeLog::write('info', 'Test 2');	

			CakeLog::write('info', 'hashBase64: ' . json_encode($orderData)); 
			//CakeLog::write('info', json_encode($info)); 
			CakeLog::write('info', 'HEADER SIZE: ' . $header_size . ', HEADER CONTENT: ' . $header); 
			curl_close($ch);

		
	}	



	public function oz_to_lbs($weight){
	   
	   	$weight = $weight / 16;

	    return $weight;
	}



	public function  get_string_between($string, $start, $end){
	    $string = ' ' . $string;
	    $ini = strpos($string, $start);
	    if ($ini == 0) return '';
	    $ini += strlen($start);
	    $len = strpos($string, $end, $ini) - $ini;
	    return substr($string, $ini, $len);
	}



	public function get_wc_product_wgt_by_sku($store_id, $lisku) {
		
        $wc_api = $this->build_wc_client($store_id);

        $prod = $wc_api->products->get_by_sku($lisku);
        $weight = $prod->product->weight;

        return $weight; 
	}



    /**
     * Use global variables defined in config/bootstrap to instantiate a WC object
     * 
     * @return WC_API_Client object
     */
    function build_wc_client($store_id=NULL) {

        $conds = array('conditions' => array('Stores.store_id' => $store_id), 'fields' => array('Stores.store_id', 'Stores.wc_key', 'Stores.wc_secret', 'Stores.wc_hook_source'));
            
        $this->loadModel('Stores');
        $store = $this->Stores->find('first', $conds);
        
        $options = Configure::read('wc_options');
        $consumer_key = $store['Stores']['wc_key']; //Configure::read('wc_key');
        $consumer_secret = $store['Stores']['wc_secret']; //Configure::read('wc_secret');
        $store_url = $store['Stores']['wc_hook_source']; //Configure::read('wc_url');

        require_once(Configure::read('wc_api_path'));
        $wc_api = new WC_API_Client( $store_url, $consumer_key, $consumer_secret, $options );
        return $wc_api;
    }


}

