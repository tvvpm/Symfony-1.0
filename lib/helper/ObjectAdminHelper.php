<?php

use_helper('Form', 'Javascript', 'Helper', 'I18N');

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * ObjectHelper for admin generator.
 *
 * @package    symfony
 * @subpackage helper
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: ObjectAdminHelper.php 9176 2008-05-22 07:44:14Z FabianLange $
 */

function object_admin_input_file_tag($object, $method, $options = array())
{
  $options = _parse_attributes($options);
  $name    = _convert_method_to_name($method, $options);

  $html = '';

  $value = _get_object_value($object, $method);

  if ($value)
  {
    if ($include_link = _get_option($options, 'include_link'))
    {
      $image_path = image_path('/'.sfConfig::get('sf_upload_dir_name').'/'.$include_link.'/'.$value);
      $image_text = ($include_text = _get_option($options, 'include_text')) ? __($include_text) : __('[show file]');

      $html .= sprintf('<a onclick="window.open(this.href);return false;" href="%s">%s</a>', $image_path, $image_text)."\n";
    }

    if ($include_remove = _get_option($options, 'include_remove'))
    {
      $html .= checkbox_tag(strpos($name, ']') !== false ? substr($name, 0, -1).'_remove]' : $name).' '.($include_remove !== true ? __($include_remove) : __('remove file'))."\n";
    }
  }

  return input_file_tag($name, $options)."\n<br />".$html;
}


function admin_double_list($name, $options, $custom_objects=array(), $objects_associated=array())
{
  $options = _parse_attributes($options);
  $options['multiple']=true;
  if (!isset($options['class']))
     $options['class']='sf_admin_multiple';
  else
     $options['class'] .= ' sf_admin_multiple';

  if (!isset($options['size']))
  {
    $options['size'] = 10;
  }
  $label_all   = __(isset($options['unassociated_label']) ? $options['unassociated_label'] : 'Unassociated');
  $label_assoc = __(isset($options['associated_label'])   ? $options['associated_label']   : 'Associated');

  $through_class = _get_option($options, 'through_class');
  $associated_ids = array_map(function($o) { return $o->getPrimaryKey();}, $objects_associated);
  $custom_ids  = array_map(function($o) { return $o->getPrimaryKey();}, $custom_objects);
  $already_asigned_ids = array();
  //Buscamos los objetos que estan asociados pero no estan en los diponibles.
  foreach($associated_ids as $index => $aid)
  {
    if (!in_array($aid, $custom_ids))
    {
      $already_asigned_ids[] = $aid;
      unset($associated_ids[$index]);
    }
  }

  //Buscamos los objetos no asociados.
  $objects_unassociated = array();
  foreach($custom_objects as $index => $object)
    if (!in_array($object->getPrimaryKey(), $associated_ids))
      $objects_unassociated[] = $object;

  $already_asigned_objects = array();
  if (!isset($options['show_already']) or ($options['show_already']))
    foreach($objects_associated as $index => $object)
      if (in_array($object->getPrimaryKey(), $already_asigned_ids))
      {
        $already_asigned_objects[] = $object;
        unset($objects_associated[$index]);
      }

  if (isset($options['hide_unavailiables']))
    foreach($objects_associated as $index => $object)
    {
      if (!in_array($object->getPrimaryKey(), $custom_ids))
        unset($objects_associated[$index]);
    }

  // remove non html option
  unset($options['through_class']);

  // override field name
  unset($options['control_name']);

  $name1 = 'unassociated_'.$name; $name1_id = get_id_from_name($name1);
  $name2 = 'associated_'.$name; $name2_id = get_id_from_name($name2);
  $name3 = 'associated_already_'.$name; $name3_id = get_id_from_name($name3);

  $select1 = select_tag($name1, options_for_select(_get_options_from_objects($objects_unassociated), '', $options), $options);
  if (!isset($options['class']))
     $options['class']='sf_admin_multiple-selected';
  else
     $options['class'] .= ' sf_admin_multiple-selected';

  $select2 = select_tag($name2, options_for_select(_get_options_from_objects($objects_associated), '', $options), $options);

  if (count($already_asigned_objects)>0)
    $already_html = sprintf(
	'<div style="float: left; margin-left: 5px;"><div style="font-weight: bold; padding-bottom: 0.5em">%s</div>%s</div>',
	__(isset($options['already_label'])) ? $options['already_label']   : 'Already associated',
	select_tag($name3, options_for_select(_get_options_from_objects($already_asigned_objects), '', $options), array_merge($options, array('readonly'=>'readonly')))
    );
  else
     $already_html ='';

  $html =
'<div>
  <div style="float: left">
    <div style="font-weight: bold; padding-bottom: 0.5em">%s</div>
    %s
  </div>
  <div style="float: left">
    %s<br />
    %s
  </div>
  <div style="float: left">
    <div style="font-weight: bold; padding-bottom: 0.5em">%s</div>
    %s
  </div>
  %s
  <br style="clear: both" />
</div>
<script>
<!--
	jQuery("#'.$name1_id.'").dblclick(function() {
		double_list_move("'. $name1_id . '", "'. $name2_id . '");
	});
	jQuery("#'.$name2_id.'").dblclick(function() {
		double_list_move("'. $name2_id . '", "'. $name1_id . '");
	});
-->
</script>
';

  $response = sfContext::getInstance()->getResponse();
  $response->addJavascript(sfConfig::get('sf_admin_web_dir').'/js/double_list.js');

  return sprintf($html,
    $label_all,
    $select1,
    submit_image_tag(sfConfig::get('sf_admin_web_dir').'/images/next.png', "style=\"border: 0\" onclick=\"double_list_move('{$name1_id}', '{$name2_id}'); return false;\""),
    submit_image_tag(sfConfig::get('sf_admin_web_dir').'/images/previous.png', "style=\"border: 0\" onclick=\"double_list_move('{$name2_id}', '{$name1_id}'); return false;\""),
    $label_assoc,
    $select2,
    $already_html
  );
}

function object_admin_double_list($object, $method, $options = array(), $callback = null)
{
  $options = _parse_attributes($options);

  $options['multiple'] = true;
  $options['class'] = 'sf_admin_multiple';
  if (isset($options['callback'])) $callback = $options['callback'];

  if (!isset($options['size']))
  {
    $options['size'] = 10;
  }
  $label_all   = __(isset($options['unassociated_label']) ? $options['unassociated_label'] : 'Unassociated');
  $label_assoc = __(isset($options['associated_label'])   ? $options['associated_label']   : 'Associated');

  // get the lists of objects
  list($all_objects, $objects_associated, $associated_ids) = _get_object_list($object, $method, $options, $callback);

  $objects_unassociated = array();

  if (isset($options['associated_ids']))
  {
    foreach ($all_objects as $object)
    {
      if (!in_array($object->getPrimaryKey(), $options['associated_ids']))
      {
        $objects_associated[] = $object;
        $associated_ids[] = $object->getPrimaryKey();
      }
      else
        $objects_unassociated[] = $object;
    }
  }
  else
  {
    foreach ($all_objects as $object)
    {
      if (!in_array($object->getPrimaryKey(), $associated_ids))
      {
        $objects_unassociated[] = $object;
      }
    }
  }

  // remove non html option
  unset($options['through_class']);
  // override field name
  unset($options['control_name']);
  $name  = _convert_method_to_name($method, $options);
  $name1 = 'unassociated_'.$name;
  $name2 = 'associated_'.$name;
  $select1 = select_tag($name1, options_for_select(_get_options_from_objects($objects_unassociated), '', $options), $options);
  $options['class'] = 'sf_admin_multiple-selected';
  $select2 = select_tag($name2, options_for_select(_get_options_from_objects($objects_associated), '', $options), $options);

  $html =
'<div>
  <div style="float: left">
    <div style="font-weight: bold; padding-bottom: 0.5em">%s</div>
    %s
  </div>
  <div style="float: left">
    %s<br />
    %s
  </div>
  <div style="float: left">
    <div style="font-weight: bold; padding-bottom: 0.5em">%s</div>
    %s
  </div>
  <br style="clear: both" />
</div>
<script>
<!--
	jQuery("#'.$name1.'").dblclick(function() {
		double_list_move("'. $name1 . '", "'. $name2 . '");
	});
	jQuery("#'.$name2.'").dblclick(function() {
		double_list_move("'. $name2 . '", "'. $name1 . '");
	});
-->
</script>
';

  $response = sfContext::getInstance()->getResponse();
  $response->addJavascript(sfConfig::get('sf_admin_web_dir').'/js/double_list.js');

  return sprintf($html,
    $label_all,
    $select1,
    submit_image_tag(sfConfig::get('sf_admin_web_dir').'/images/next.png', "style=\"border: 0\" onclick=\"double_list_move('{$name1}', '{$name2}'); return false;\""),
    submit_image_tag(sfConfig::get('sf_admin_web_dir').'/images/previous.png', "style=\"border: 0\" onclick=\"double_list_move('{$name2}', '{$name1}'); return false;\""),
    $label_assoc,
    $select2
  );
}

function object_admin_select_list($object, $method, $options = array(), $callback = null)
{
  $options = _parse_attributes($options);

  $options['multiple'] = true;
  $options['class'] = 'sf_admin_multiple';
  if (!isset($options['size']))
  {
    $options['size'] = 10;
  }

  // get the lists of objects
  list($objects, $objects_associated, $ids) = _get_object_list($object, $method, $options, $callback);
  // remove non html option
  unset($options['through_class']);
  // override field name
  unset($options['control_name']);
  $name = 'associated_'._convert_method_to_name($method, $options);

  return select_tag($name, options_for_select(_get_options_from_objects($objects), $ids, $options), $options);
}

function object_admin_check_list($object, $method, $options = array(), $callback = null)
{
  $options = _parse_attributes($options);

  // get the lists of objects
  list($objects, $objects_associated, $assoc_ids) = _get_object_list($object, $method, $options, $callback);

  // override field name
  unset($options['control_name']);
  $name = 'associated_'._convert_method_to_name($method, $options).'[]';
  $html = '';

  if (!empty($objects))
  {
    // which method to call?
    $methodToCall = '__toString';
    foreach (array('__toString', 'toString', 'getPrimaryKey') as $method)
    {
      if (method_exists($objects[0], $method))
      {
        $methodToCall = $method;
        break;
      }
    }

    $html .= "<ul class=\"sf_admin_checklist\">\n";
    foreach ($objects as $related_object)
    {
      $relatedPrimaryKey = $related_object->getPrimaryKey();

      // multi primary key handling
      if (is_array($relatedPrimaryKey))
      {
        $relatedPrimaryKeyHtmlId = implode('/', $relatedPrimaryKey);
      }
      else
      {
        $relatedPrimaryKeyHtmlId = $relatedPrimaryKey;
      }

      $html .= '<li>'.checkbox_tag($name, $relatedPrimaryKeyHtmlId, in_array($relatedPrimaryKey, $assoc_ids)).' <label for="'.get_id_from_name($name, $relatedPrimaryKeyHtmlId).'">'.$related_object->$methodToCall()."</label></li>\n";
    }
    $html .= "</ul>\n";
  }

  return $html;
}

function _get_propel_object_list($object, $method, $options)
{
  // get the lists of objects
  $through_class = _get_option($options, 'through_class');

  $objects = sfPropelManyToMany::getAllObjects($object, $through_class);
  $objects_associated = sfPropelManyToMany::getRelatedObjects($object, $through_class);
  $ids = array_map(function($o) { return $o->getPrimaryKey();}, $objects_associated);

  return array($objects, $objects_associated, $ids);
}

function _get_object_list($object, $method, $options, $callback)
{
  $object = $object instanceof sfOutputEscaper ? $object->getRawValue() : $object;

  // the default callback is the propel one
  if (!$callback)
  {
    $callback = '_get_propel_object_list';
  }

  return call_user_func($callback, $object, $method, $options);
}
