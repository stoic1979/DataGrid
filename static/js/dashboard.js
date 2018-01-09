$(document).ready(function(){
  var currentPage = $('body').attr('data-current-page');
  if (currentPage) {
    $('.dashboard-sidebar [data-page='+currentPage+']').addClass('dashboard-sidebar-active');
  }

  $('.dashboard-sidebar-menu > ul > li ul').hide();

  $('.dashboard-sidebar-toggle').click(function(){
    $(this).nextAll('ul').slideToggle(300);
  });
});
