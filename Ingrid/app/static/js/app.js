// data types & common stuff
var STATUS = {

    OK               : 0 ,
    ERR              : 1 ,
    ERR_AUTH         : 2 ,
    ERR_INPUT        : 3 ,

};

// data types & common stuff
var COMMON = {

    SECTION_SETTINGS                : 'SECTION_SETTINGS',
    OPER_UPDATE_NAME                : 'UPDATE_NAME'     ,
    OPER_UPDATE_USERNAME            : 'UPDATE_USERNAME' ,
    OPER_UPDATE_COMPANY             : 'UPDATE_COMPANY' ,
    OPER_UPDATE_EMAIL               : 'UPDATE_EMAIL'    ,
    OPER_UPDATE_PASS                : 'UPDATE_PASS'     ,

    SECTION_DASHBOARD               : 'SECTION_DASHBOARD',
    OPER_DASHBOARD_PLANT_OPERATIONS : 'DASHBOARD_PLANT_OPERATIONS',

};

// class / var to be used in ajax calls
var ajx_INPUT = {
    'section'           : '',
    'action'            : '',
    'html_target'       : '',
    'data'              : '',
    'data2'             : '',
    'data3'             : '',
    'data4'             : '',
    'data5'             : '',
};


function notif( status, text ) {

    let notif_class = 'success';

    if ( status == STATUS.OK ) {

        $('span#notif').css( 'color', 'blue' );

    } else {

        $('span#notif').css( 'color', 'red' );

    }


    $('span#notif').html( text );
}

// helper to talk to backend using ajax ..
function ajx_router( section, action, data, data2, callback_fct ) {

    ajx_INPUT.section       = section ;
    ajx_INPUT.action        = action  ;
    ajx_INPUT.data          = data    ;
    ajx_INPUT.data2         = data2   ;

    $.ajax({
        url       : '/api'    ,
        data      : ajx_INPUT ,
        dataType  : 'json'    ,
        type      : 'POST'    ,
        success   : function( resp_json ) {

            console.log( resp_json );

            callback_fct( resp_json );

        },
        error: function(error) {

            console.log(error);

        }
    });
}

// callback for assignments ..
function callbk_common( resp_json ) {

    console.log('[callbk_common] Begin' );
    console.log('[callbk_common] section     -> ' + resp_json.section     );
    console.log('[callbk_common] action      -> ' + resp_json.action      );
    console.log('[callbk_common] status      -> ' + resp_json.status      );
    console.log('[callbk_common] status_info -> ' + resp_json.status_info );
    
    // print only if we have some ..
    if ( resp_json.data )
        console.log('[callbk_common] data        -> ' + resp_json.data        );

    notif( resp_json.status, resp_json.status_info );
    

    if (    (resp_json.status == STATUS.OK) 
        &&  (resp_json.action == COMMON.OPER_UPDATE_NAME    ||
             resp_json.action == COMMON.OPER_UPDATE_USERNAME||
             resp_json.action == COMMON.OPER_UPDATE_COMPANY ||
             resp_json.action == COMMON.OPER_UPDATE_PASS    ||
             resp_json.action == COMMON.OPER_UPDATE_EMAIL ) ) {
            
        setTimeout(function(){
            console.log(' *** sleep *** ');
        }, 1000);

        location.reload();
    }

}

function dashboard_plant_oper( oper_code ) {
    ajx_router( COMMON.SECTION_DASHBOARD, COMMON.OPER_DASHBOARD_PLANT_OPERATIONS, oper_code, null/*data2*/, callbk_dashboard_plant_oper );

    $('.dashboard-sidebar-active').removeClass('dashboard-sidebar-active');
    $('.dashboard-sidebar [data-page=plant-'+oper_code+']').addClass('dashboard-sidebar-active');
}

// callback for assignments ..
function callbk_dashboard_plant_oper( resp_json ) {
    console.log('[callbk_common] Begin' );
    console.log('[callbk_common] section     -> ' + resp_json.section     );
    console.log('[callbk_common] action      -> ' + resp_json.action      );
    console.log('[callbk_common] status      -> ' + resp_json.status      );
    console.log('[callbk_common] status_info -> ' + resp_json.status_info );
    console.log('[callbk_common] data        -> ' + resp_json.data        );
    console.log('[callbk_common] response    -> ' + resp_json.response    );

    // inject response
    $('#dashboard_target').html( resp_json.response );
}

function update_name( user_id ) {

    console.log( 'update name for user = ' + user_id );

    let data = $('input#settings_name').val();

    ajx_router( COMMON.SECTION_SETTINGS /*section*/,
                COMMON.OPER_UPDATE_NAME /*action*/,
                user_id                 /*user_id*/,
                data                    /*data*/,
                callbk_common           /*callback*/ );
}

function update_user( user_id ) {

    console.log( 'update username for user = ' + user_id );

    let data = $('input#settings_username').val();

    ajx_router( COMMON.SECTION_SETTINGS     /*section*/,
                COMMON.OPER_UPDATE_USERNAME /*action*/,
                user_id                     /*user_id*/,
                data                        /*data*/,
                callbk_common               /*callback*/ );
}

function update_company( user_id ) {

    console.log( 'update company for user = ' + user_id );

    let data = $('input#settings_company').val();

    ajx_router( COMMON.SECTION_SETTINGS     /*section*/,
                COMMON.OPER_UPDATE_COMPANY  /*action*/,
                user_id                     /*user_id*/,
                data                        /*data*/,
                callbk_common               /*callback*/ );
}


function update_email( user_id ) {

    console.log( 'update email for user = ' + user_id );

    let data = $('input#settings_email').val();

    ajx_router( COMMON.SECTION_SETTINGS     /*section*/,
                COMMON.OPER_UPDATE_EMAIL    /*action*/,
                user_id                     /*user_id*/,
                data                        /*data*/,
                callbk_common               /*callback*/ );
}

function update_pass( user_id ) {

    console.log( 'update pass for user = ' + user_id );

    let pass   = $('input#settings_pass'   ).val();
    let pass_c = $('input#settings_pass_c' ).val();

    if ( !pass || !pass_c || ( pass !== pass_c ) )
    {

        $('span#notif').css( 'color', 'red' );
        $('span#notif').html( 'Wrong input to change password' );
        return;
    }

    ajx_router( COMMON.SECTION_SETTINGS     /*section*/,
                COMMON.OPER_UPDATE_PASS     /*action*/,
                user_id                     /*user_id*/,
                pass                        /*data*/,
                callbk_common               /*callback*/ );
}

function update_bio( user_id ) {

        console.log( 'update user -> ' + user_id );

        let data      = $('input#settings_bio').val();

        ajx_router( COMMON.SECTION_SETTINGS /*section*/,
                    COMMON.OPER_UPDATE_BIO  /*action*/,
                    user_id /*user_id*/,
                    data /*data*/,
                    callbk_common /*callback*/ );

    }

// process a assignment deletion
$( "#settings_update_name" ).click(function() {
    update_name();
});

$( "#settings_update_username" ).click(function() {
    update_username();
});

$( "#settings_update_company" ).click(function() {
    update_company();
});

$( "#settings_update_email" ).click(function() {
    update_email();
});

$( "#settings_update_pass" ).click(function() {
    update_pass();
});


