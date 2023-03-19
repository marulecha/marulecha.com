/* drop down menu */
var dropdown = document.getElementsByClassName("dropdown-btn-2");

var i;

for (i = 0; i < dropdown.length; i++) {
  dropdown[i].addEventListener("click", function() {
   var container = document.getElementsByClassName("dropdown-container-2");
   var dropdownContent = this.nextElementSibling; 
   
   if(dropdownContent.style.display == "block") {
      dropdownContent.style.display = "none";
      return; 
   } 
    
    
   for (var j = 0; j < container.length; j++) {
     if(container[j].style.display = "block") {
         container[j].style.display = "none";
      }
   }
   
   dropdownContent.style.display = "block";
   
  });
}

/* checklist object */

