
function double_list_move(src, dest)
{
  src=document.getElementById(src);
  dest=document.getElementById(dest);
  for (var i = 0; i < src.length; i++)
  {
    if (src.options[i].selected)
    {
      dest.options[dest.length] = new Option(src.options[i].text, src.options[i].value);
      src.options[i] = null;
      --i;
    }
  }
}

function double_list_submit(form_name)
{
  // default id to allow using a custom form id
  if( ! form_name ) {
    var form_name = 'sf_admin_edit_form';
  }

  var form = document.getElementById(form_name);
  var element;

  // find multiple selects with name beginning 'associated_' and select all their options
  for (var i = 0; i < form.elements.length; i++)
  {
    element = form.elements[i];
    if (element.type == 'select-multiple')
    {
      if (element.classList.contains('sf_admin_multiple-selected'))
      {
        element.removeAttribute('disabled')
        for (var j = 0; j < element.options.length; j++)
        {
          element.options[j].selected = true;
        }
      }
    }
  }
}
