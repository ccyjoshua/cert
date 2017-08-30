// Take enter key same as search button
$(function () {
    $("#keywordInput").keyup(function(event){
        if(event.keyCode == 13){
            searchButtonOnClick();
        }
    });
});

function searchButtonOnClick() {
    var keyword = $('#keywordInput').val();
    //console.log(keyword);
    // $('#keywordSpan').html(keyword);
    $('#load').button('loading');
    location.href = '/?keyword=' + keyword;
}
