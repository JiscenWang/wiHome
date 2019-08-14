

/************************************************************************************
* icomera_user.js
* Created 2013-10-29 by Martin Lindahl
*
* A javascript for supporting user API usage
*
* Classes to be used:
* - user-online				Use to define sections when user is online
* - user-offline			Use to define sections when user is offline
* - user-class-span			Span used to display user class (0,1,2)
* - user-ip-span			Span used to display the IP address
* - user-mac-span			Span used to display the MAC address
* - quota-time-left-span	Span used to display the time left online
* - quota-time-used-span	Span used to display the time online
* - quota-limitation-bar	The limitation bar, showing the usage
* - quota-limitation-span 	Span used to display the current limit
* - quota-usage-span		Span used to display current usage
* - quota-usage-left-span 	Span used to display usage left with current limit
* - quota-unthrottled		Use to define sections when user is not throttled
* - quota-throttled			Use to define sections when user is throttled
*
*
*************************************************************************************/

var _user = {};
var _criteriaForThrottled;
var _operatorForThrottled;
var _valueForThrottled;
var _isThrottled;
var _isLimited;

(function($) {
	$(document).ready(function(){

        _criteriaForThrottled = "bandwidth_download_limit";
        _operatorForThrottled = "<";
				_isLimited = true;
        _valueForThrottled = 0;
        _isThrottled = false;

        $(document).bind('user_update',null,updateUserQuotas);
        $(document).bind('user_update',null,updateUserDetails);
		updateUser();

		_user.updateinterval = setInterval("updateUser()",10000);
	});

	this.updateUser = function()
	{
		/**
		 * Response holds the following keys:
		 * --------------------------------------------------------------------------------
		 * KEY		                EXAMPLE			 NOTE
		 * --------------------------------------------------------------------------------
		 * ip		                10.101.1.2
		 * mac		                00:11:22:33:44:55
		 * online	                900				 Time left on account to stay online
		 * userclass                2				 1=First class, 2=Second class
	     * version                  1.4
	     * timeleft                 300
	     * authenticated            1
	     * expires                  Never
	     * timeused                 100
	     * data_download_used       300
	     * data_upload_used         200
	     * data_total_used          500
	     * data_download_limit      1024
	     * data_upload_limit        2048
	     * data_total_limit         3072
	     * bandwidth_download_limit 128
         * bandwidth_upload_limit   256
		 * --------------------------------------------------------------------------------
		 */
		$.getJSON("http://www.ombord.info/api/jsonp/user/?callback=?",function(response) {
			// Save data
            _user.version                   = response.version;
			_user.ip	                    = response.ip;
			_user.mac	                    = response.mac;
			_user.authenticated				= parseInt(response.authenticated);
			_user.userclass	                = parseInt(response.userclass);
			_user.timeused                  = parseInt(response.timeused);
			_user.data_download_used        = parseInt(response.data_download_used);
			_user.data_upload_used          = parseInt(response.data_upload_used);
			_user.data_total_used           = parseInt(response.data_total_used);
			_user.data_download_limit       = parseInt(response.data_download_limit);
			_user.data_upload_limit         = parseInt(response.data_upload_limit);
			_user.data_total_limit          = parseInt(response.data_total_limit);
			_user.bandwidth_download_limit  = parseInt(response.bandwidth_download_limit);
			_user.bandwidth_upload_limit    = parseInt(response.bandwidth_upload_limit);
			_user.expires                   = response.expires;
			_user.timeleft                  = parseInt(response.timeleft);

			$(document).trigger('user_update');
		});
	};

	this.updateLimitationBars = function()
	{
        $('.quota-limitation-bar').each(function() {
            var me = $(this);
            var perc = 0;
            if (_isThrottled)
            {
                perc = 100;
                //$(document).trigger('user_throttled');
            }
            else
            {
                perc = getUserDataPercentage();
            }
            //console.log("isThrottled = " + _isThrottled + ", User percentage: " + perc);
            me.css('width', (perc)+'%');
        });
    };

	this.updateLimitationSpans = function()
	{
	 	if(isNaN(_user.data_total_limit) || isNaN(_user.data_total_used)){
	 		$('.quota-invalid').each(function() {
	 			$(this).show();
	    });
			$('.quota-valid').each(function() {
	 			$(this).hide();
	    });
	 	}
	 	else{
	 		$('.quota-invalid').each(function() {
	 			$(this).hide();
	    });
			$('.quota-valid').each(function() {
		 		$(this).show();
		  });
	    $('.quota-limitation-span').each(function() {
        var me = $(this);
        var limitMB = Math.floor(_user.data_total_limit/(1024*1024));
        me.html(limitMB);
      });
      $('.quota-usage-span').each(function() {
        var me = $(this);
        var usageMB = Math.floor(_user.data_total_used/(1024*1024));
        me.html(usageMB);
      });
      $('.quota-usage-left-span').each(function() {
        var me = $(this);
        var usageMB = Math.ceil((_user.data_total_limit - _user.data_total_used)/(1024*1024));
        me.html(usageMB);
      });
	 	}
	};

	this.updateUserQuotas = function()
	{
	  updateThrottledStatus();
	  updateLimitationBars();
	  updateLimitationSpans();
		updateTimeSpans();
	};

	this.updateTimeSpans = function()
	{
	  $('.quota-time-left-span').each(function() {
      var me = $(this);
      me.html(_user.timeleft);
	  });
	  $('.quota-time-used-span').each(function() {
      var me = $(this);
      me.html(_user.timeused);
	  });
	};

	this.updateUserDetails = function()
	{
	  $('.user-online').each(function() {
      var me = $(this);
      if (_user.authenticated)
          me.show();
      else
          me.hide();
	  });

	  $('.user-offline').each(function() {
      var me = $(this);
      if (_user.authenticated)
          me.hide();
      else
          me.show();
	  });

	  $('.user-class-span').each(function() {
      var me = $(this);
      me.html(_user.userclass);
	  });

	  $('.user-ip-span').each(function() {
      var me = $(this);
      me.html(_user.ip);
	  });

	  $('.user-mac-span').each(function() {
      var me = $(this);
      me.html(_user.mac);
	  });
	};

  this.getUserDataPercentage = function()
  {
    var perc = Math.ceil((_user.data_total_used / _user.data_total_limit) * 100);
    return perc;
  };

  this.updateThrottledStatus = function()
  {
    if (_criteriaForThrottled == "bandwidth_download_limit")
    {
      if (_operatorForThrottled == ">")
      {
        _isThrottled = (_user.bandwidth_download_limit > _valueForThrottled);
      }
      else if (_operatorForThrottled == "<")
      {
        _isThrottled = _user.bandwidth_download_limit < _valueForThrottled;
      }
      else
      {
        _isThrottled = _user.bandwidth_download_limit == _valueForThrottled;
      }
    }
    else
    {
      _isThrottled = false;
    }
    //console.log("updateThrottledStatus: _isThrottled = " + _isThrottled);


		$('.quota-unlimitted').each(function() {
			var me = $(this);
			if (!_isLimited)
				me.show();
			else
				me.hide();
		});

		$('.quota').each(function() {
			var me = $(this);
			if(_isLimited)
				me.show();
			else
				me.hide();
		});

    $('.quota-unthrottled').each(function() {
      var me = $(this);
      if (!_isThrottled)
        me.show();
      else
        me.hide();
    });

    $('.quota-throttled').each(function() {
      var me = $(this);
      if (_isThrottled)
        me.show();
      else
        me.hide();
		});
	};
})(jQuery);
